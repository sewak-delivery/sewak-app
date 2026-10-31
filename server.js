import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Razorpay from "razorpay";
import crypto from "node:crypto";
import { z } from "zod";
import { query, pool } from "./db.js";
import { requireAuth, allowRoles, signToken } from "./auth.js";
import { createOtp, verifyOtp } from "./otp.js";

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) throw new Error("Set JWT_SECRET to a random value at least 32 characters long");
const app = express();
app.use(helmet());
app.use(cors({ origin: (process.env.CORS_ORIGIN || "http://localhost:8080").split(",").map(x=>x.trim()) }));
app.use(express.json({ limit: "100kb", verify: (req, _res, buf) => { req.rawBody = Buffer.from(buf); } }));
app.use(express.static("public"));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const orderLimiter = rateLimit({ windowMs: 60*1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const phoneSchema = z.string().regex(/^[0-9]{10}$/);
const areaSchema = z.enum(["Dalmau","Murai Bagh"]);
const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;

app.get("/api/health", (_req,res)=>res.json({ok:true,service:"SEWAK API",mode:process.env.NODE_ENV||"development"}));

app.post("/api/auth/request-otp", authLimiter, async (req,res,next)=>{
  try {
    const phone = phoneSchema.safeParse(req.body.phone);
    if (!phone.success) return res.status(400).json({error:"Enter a valid 10-digit Indian mobile number"});
    await createOtp(phone.data);
    res.json({ok:true,message:"OTP requested. In local development, check server console."});
  } catch(e) { if(e.message.includes("Too many")) return res.status(429).json({error:e.message}); next(e); }
});
app.post("/api/auth/verify-otp", authLimiter, async (req,res,next)=>{
  try {
    const phone=phoneSchema.safeParse(req.body.phone), code=z.string().regex(/^[0-9]{6}$/).safeParse(req.body.code);
    if(!phone.success||!code.success) return res.status(400).json({error:"Valid phone and 6-digit OTP are required"});
    if(!(await verifyOtp(phone.data,code.data))) return res.status(401).json({error:"OTP invalid or expired"});
    const r=await query(`INSERT INTO users(phone) VALUES($1) ON CONFLICT(phone) DO UPDATE SET phone=EXCLUDED.phone RETURNING id,phone,name,role`,[phone.data]);
    const user=r.rows[0];
    res.json({token:signToken(user),user});
  } catch(e){next(e);}
});
app.get("/api/me",requireAuth,(req,res)=>res.json({user:req.user}));

app.get("/api/shops",async(req,res,next)=>{
  try {
    const area= req.query.area ? areaSchema.safeParse(req.query.area) : null;
    if(area && !area.success) return res.status(400).json({error:"Area must be Dalmau or Murai Bagh"});
    const params=[],where=["is_open=TRUE"];
    if(area){params.push(area.data);where.push(`area=$${params.length}`);}
    if(req.query.category){params.push(String(req.query.category));where.push(`category=$${params.length}`);}
    const r=await query(`SELECT id,name_hi,name_en,category,address,area,phone,is_open FROM shops WHERE ${where.join(" AND ")} ORDER BY name_en`,params);
    res.json({shops:r.rows});
  }catch(e){next(e);}
});
app.get("/api/shops/:id/products",async(req,res,next)=>{
  try {const r=await query("SELECT id,shop_id,name_hi,name_en,description,price_paise,stock_qty FROM products WHERE shop_id=$1 AND active=TRUE AND stock_qty>0 ORDER BY name_en",[req.params.id]);res.json({products:r.rows});}
  catch(e){next(e);}
});

app.post("/api/orders",requireAuth,orderLimiter,async(req,res,next)=>{
  const schema=z.object({
    shop_id:z.string().uuid(),
    items:z.array(z.object({product_id:z.string().uuid(),quantity:z.number().int().min(1).max(50)})).min(1).max(50),
    customer_name:z.string().trim().min(2).max(100),
    customer_phone:phoneSchema,
    address:z.string().trim().min(5).max(500),
    area:areaSchema,
    payment_method:z.enum(["cash","online"]).default("cash"),
    notes:z.string().max(500).optional()
  });
  const parsed=schema.safeParse(req.body);
  if(!parsed.success)return res.status(400).json({error:"Invalid order details",details:parsed.error.flatten()});
  const data=parsed.data;
  if(data.payment_method==="online"&&!razorpay)return res.status(503).json({error:"Online payment is not configured yet"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const shopR=await client.query("SELECT id,area,is_open FROM shops WHERE id=$1 FOR UPDATE",[data.shop_id]);
    const shop=shopR.rows[0];
    if(!shop||!shop.is_open||shop.area!==data.area){await client.query("ROLLBACK");return res.status(400).json({error:"Shop unavailable in selected area"});}
    let subtotal=0,items=[];
    for(const item of data.items){
      const pr=await client.query("SELECT id,name_hi,name_en,price_paise,stock_qty FROM products WHERE id=$1 AND shop_id=$2 AND active=TRUE FOR UPDATE",[item.product_id,data.shop_id]);
      const p=pr.rows[0];
      if(!p||p.stock_qty<item.quantity){await client.query("ROLLBACK");return res.status(400).json({error:"Product unavailable or insufficient stock",product_id:item.product_id});}
      subtotal+=p.price_paise*item.quantity;items.push({...item,product:p});
    }
    const deliveryFee=0; // Set the approved SEWAK fee policy before launch.
    const total=subtotal+deliveryFee;
    const ord=await client.query(`INSERT INTO orders(customer_user_id,shop_id,status,payment_method,payment_status,subtotal_paise,delivery_fee_paise,total_paise,customer_name,customer_phone,address,area,notes)
      VALUES($1,$2,'placed',$3,'pending',$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,order_number,status,total_paise,created_at`,
      [req.user.id,data.shop_id,data.payment_method,subtotal,deliveryFee,total,data.customer_name,data.customer_phone,data.address,data.area,data.notes||null]);
    const order=ord.rows[0];
    for(const item of items){
      await client.query(`INSERT INTO order_items(order_id,product_id,product_name_hi,product_name_en,unit_price_paise,quantity,line_total_paise) VALUES($1,$2,$3,$4,$5,$6,$7)`,
        [order.id,item.product.id,item.product.name_hi,item.product.name_en,item.product.price_paise,item.quantity,item.product.price_paise*item.quantity]);
      await client.query("UPDATE products SET stock_qty=stock_qty-$1 WHERE id=$2",[item.quantity,item.product.id]);
    }
    await client.query("COMMIT");
    let payment=null;
    if(data.payment_method==="online"){
      try{
        const rp=await razorpay.orders.create({amount:total,currency:"INR",receipt:String(order.order_number),notes:{sewak_order_id:order.id}});
        await query("UPDATE orders SET razorpay_order_id=$1 WHERE id=$2",[rp.id,order.id]);
        payment={provider:"razorpay",key_id:process.env.RAZORPAY_KEY_ID,razorpay_order_id:rp.id,amount:rp.amount,currency:rp.currency};
      }catch(e){await query("UPDATE orders SET payment_status='failed' WHERE id=$1",[order.id]);return res.status(502).json({error:"Payment order could not be created; contact support with order number",order});}
    }
    res.status(201).json({order,payment});
  }catch(e){await client.query("ROLLBACK").catch(()=>{});next(e);}finally{client.release();}
});

app.get("/api/orders/my",requireAuth,async(req,res,next)=>{
  try{const r=await query(`SELECT o.id,o.order_number,o.status,o.payment_method,o.payment_status,o.total_paise,o.address,o.area,o.created_at,s.name_hi AS shop_name_hi,s.name_en AS shop_name_en
  FROM orders o JOIN shops s ON s.id=o.shop_id WHERE o.customer_user_id=$1 ORDER BY o.created_at DESC LIMIT 100`,[req.user.id]);res.json({orders:r.rows});}catch(e){next(e);}
});
app.get("/api/orders/:id",requireAuth,async(req,res,next)=>{
  try{const r=await query("SELECT * FROM orders WHERE id=$1 AND (customer_user_id=$2 OR delivery_user_id=$2 OR $3='admin' OR $3='shop_owner')",[req.params.id,req.user.id,req.user.role]);if(!r.rows[0])return res.status(404).json({error:"Order not found"});const items=await query("SELECT product_name_hi,product_name_en,unit_price_paise,quantity,line_total_paise FROM order_items WHERE order_id=$1",[req.params.id]);res.json({order:r.rows[0],items:items.rows});}catch(e){next(e);}
});

// Shop owner: view orders for their registered shop.
app.get("/api/shop/orders",requireAuth,allowRoles("shop_owner","admin"),async(req,res,next)=>{
  try{const r=await query(`SELECT o.* FROM orders o JOIN shops s ON s.id=o.shop_id WHERE ($1='admin' OR s.owner_user_id=$2) ORDER BY o.created_at DESC LIMIT 100`,[req.user.role,req.user.id]);res.json({orders:r.rows});}catch(e){next(e);}
});
app.patch("/api/shop/orders/:id/status",requireAuth,allowRoles("shop_owner","admin"),async(req,res,next)=>{
  try{
    const status=z.enum(["accepted","preparing","ready","cancelled"]).safeParse(req.body.status);
    if(!status.success)return res.status(400).json({error:"Invalid shop order status"});
    const r=await query(`UPDATE orders o SET status=$1,updated_at=NOW() WHERE o.id=$2 AND EXISTS(SELECT 1 FROM shops s WHERE s.id=o.shop_id AND ($3='admin' OR s.owner_user_id=$4)) RETURNING o.*`,[status.data,req.params.id,req.user.role,req.user.id]);
    if(!r.rows[0])return res.status(404).json({error:"Order not found or not your shop"});
    res.json({order:r.rows[0]});
  }catch(e){next(e);}
});

// Delivery partners see only unassigned ready orders or orders assigned to them.
app.get("/api/delivery/orders",requireAuth,allowRoles("delivery","admin"),async(req,res,next)=>{
  try{const r=await query(`SELECT id,order_number,status,total_paise,customer_name,customer_phone,address,area,created_at FROM orders WHERE status IN ('ready','picked_up') AND (delivery_user_id IS NULL OR delivery_user_id=$1) ORDER BY created_at`,[req.user.id]);res.json({orders:r.rows});}catch(e){next(e);}
});
app.post("/api/delivery/orders/:id/claim",requireAuth,allowRoles("delivery"),async(req,res,next)=>{
  try{const r=await query(`UPDATE orders SET delivery_user_id=$1,status='picked_up',updated_at=NOW() WHERE id=$2 AND status='ready' AND delivery_user_id IS NULL RETURNING id,order_number,status`,[req.user.id,req.params.id]);if(!r.rows[0])return res.status(409).json({error:"Order already claimed or not ready"});res.json({order:r.rows[0]});}catch(e){next(e);}
});
app.patch("/api/delivery/orders/:id/status",requireAuth,allowRoles("delivery","admin"),async(req,res,next)=>{
  try{const status=z.enum(["picked_up","delivered"]).safeParse(req.body.status);if(!status.success)return res.status(400).json({error:"Status must be picked_up or delivered"});const r=await query(`UPDATE orders SET status=$1,updated_at=NOW() WHERE id=$2 AND ($3='admin' OR delivery_user_id=$4) AND status IN ('ready','picked_up') RETURNING id,order_number,status`,[status.data,req.params.id,req.user.role,req.user.id]);if(!r.rows[0])return res.status(404).json({error:"Order not found or not assigned to you"});res.json({order:r.rows[0]});}catch(e){next(e);}
});

// Razorpay webhook: configure this exact URL and secret in Razorpay dashboard.
// In production, use raw-body verification middleware for the webhook route.
app.post("/api/payments/razorpay/webhook",(req,res,next)=>{ req.body=req.rawBody||Buffer.alloc(0); next(); },async(req,res,next)=>{
  try{
    const secret=process.env.RAZORPAY_WEBHOOK_SECRET;
    if(!secret)return res.status(503).send("Webhook secret not configured");
    const signature=req.headers["x-razorpay-signature"];
    const expected=crypto.createHmac("sha256",secret).update(req.body).digest("hex");
    if(typeof signature!=="string"||signature.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(signature),Buffer.from(expected)))return res.status(400).send("Invalid signature");
    const event=JSON.parse(req.body.toString("utf8"));
    const eventId=req.headers["x-razorpay-event-id"]||null;
    const payment=event.payload?.payment?.entity;
    const rpOrderId=payment?.order_id;
    const found=rpOrderId?await query("SELECT id FROM orders WHERE razorpay_order_id=$1",[rpOrderId]):{rows:[]};
    await query("INSERT INTO payment_events(provider,provider_event_id,order_id,event_type,payload) VALUES('razorpay',$1,$2,$3,$4) ON CONFLICT(provider_event_id) DO NOTHING",[eventId,found.rows[0]?.id||null,event.event||"unknown",event]);
    if(found.rows[0]&&event.event==="payment.captured")await query("UPDATE orders SET payment_status='paid',updated_at=NOW() WHERE id=$1",[found.rows[0].id]);
    if(found.rows[0]&&event.event==="payment.failed")await query("UPDATE orders SET payment_status='failed',updated_at=NOW() WHERE id=$1",[found.rows[0].id]);
    res.json({received:true});
  }catch(e){next(e);}
});

app.use((req,res)=>res.status(404).json({error:"Not found"}));
app.use((err,req,res,_next)=>{console.error(err);res.status(500).json({error:process.env.NODE_ENV==="production"?"Internal server error":err.message});});
const port=Number(process.env.PORT||8080);
app.listen(port,()=>console.log(`SEWAK API listening on port ${port}`));

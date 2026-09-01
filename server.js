const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const SECRET_KEY = "Sada@Agency_Secret_Key_2026";

// الاتصال بقاعدة البيانات السحابية برابط الحساب Sada_Admin
mongoose.connect('mongodb+srv://sada_admin:Sada%402026%23Secure_Pass99!@cluster0.hrvqt9v.mongodb.net/sada_agency?appName=Cluster0')
  .then(async () => {
      console.log("تم الاتصال بقاعدة البيانات السحابية بنجاح");
      try {
          // 1. تحديث أو إنشاء حساب المشرف الرئيسي لضمان مطابقة كلمة المرور
          await User.findOneAndUpdate(
              { username: "sada_admin" },
              { username: "sada_admin", password: "Sada@2026#Secure_Pass99!", role: "ADMIN" },
              { upsert: true, new: true }
          );

          // 2. تهيئة وتثبيت جدول الزيارات الأولي في قاعدة البيانات إذا لم يكن موجوداً
          const existingStat = await Stat.findOne({ key: 'global_visits' });
          if (!existingStat) {
              await new Stat({ key: 'global_visits', visits: 0 }).save();
              console.log("تم إنشاء سجل الزيارات الأولي بنجاح");
          }

          // 3. إضافة حقول (views: 0) والتثبيت لجميع الأخبار السابقة تلقائياً
          await Post.updateMany(
              { views: { $exists: false } },
              { $set: { views: 0, status: 'published', isPinned: false } }
          );
          console.log("تم تحديث وتهيئة حقول المشاهدات لجميع الأخبار");

      } catch (e) {
          console.log("خطأ في التهيئة التلقائية:", e);
      }
  })
  .catch(err => console.log("خطأ في الاتصال بقاعدة البيانات:", err));

// 1. جدول المستخدمين (يشمل الآدمن والمعلنين واستعادة كلمة المرور)
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String },
    phone: { type: String },
    password: { type: String, required: true },
    role: { type: String, default: 'ADVERTISER' }, // ADMIN or ADVERTISER
    resetOtp: { type: String },
    resetExpires: { type: Date }
});
const User = mongoose.model('User', UserSchema);

// 2. جدول الأخبار المحدّث
const PostSchema = new mongoose.Schema({
    title: String,
    category: String,
    mediaType: String,
    mediaUrls: [String], 
    content: String,
    status: { type: String, default: 'published' }, // منشور أو مسودة
    isPinned: { type: Boolean, default: false },    // تثبيت الخبر
    views: { type: Number, default: 0 },           // عدد المشاهدات الحقيقية
    date: { type: String, default: () => new Date().toISOString().split('T')[0] }
});
const Post = mongoose.model('Post', PostSchema);

// 3. جدول إحصائيات الزيارات الموحدة
const StatSchema = new mongoose.Schema({
    key: { type: String, default: 'global_visits' },
    visits: { type: Number, default: 0 }
});
const Stat = mongoose.model('Stat', StatSchema);

// 4. جدول طلبات الإعلانات المرتبطة بحساب المعلن
const AdBookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    orderId: String,
    name: String,
    phone: String,
    title: String,
    content: String,
    link: String,
    package: String,
    isTicker: Boolean,
    totalPrice: Number,
    imageUrl: String,
    status: { type: String, default: 'pending' }, // pending, approved, rejected
    date: { type: String, default: () => new Date().toISOString().split('T')[0] }
});
const AdBooking = mongoose.model('AdBooking', AdBookingSchema);

// Middleware لحماية مسارات لوحة التحكم
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "غير مصرح لك بالوصول" });
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "الجلسة منتهية" });
        req.user = decoded;
        next();
    });
};

// ==========================================
// مسارات حسابات المعلنين والتسجيل
// ==========================================

// تسجيل معلن جديد
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, phone, password } = req.body;
        const normalizedUsername = (username || '').trim().toLowerCase();
        
        const existing = await User.findOne({ 
            $or: [{ username: normalizedUsername }, { email: email.toLowerCase() }] 
        });
        if (existing) {
            return res.status(400).json({ error: "اسم المستخدم أو البريد الإلكتروني مسجل مسبقاً" });
        }

        const newUser = new User({
            username: normalizedUsername,
            email: (email || '').toLowerCase(),
            phone,
            password,
            role: 'ADVERTISER'
        });
        await newUser.save();

        const token = jwt.sign({ id: newUser._id, username: newUser.username, role: newUser.role }, SECRET_KEY, { expiresIn: '15d' });
        res.json({ token, user: { username: newUser.username, email: newUser.email, phone: newUser.phone } });
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

// تسجيل دخول المعلن
app.post('/api/advertiser/login', async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;
        const searchKey = (usernameOrEmail || '').trim().toLowerCase();

        const user = await User.findOne({
            $or: [{ username: searchKey }, { email: searchKey }]
        });

        if (!user || password !== user.password) {
            return res.status(400).json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة" });
        }

        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '15d' });
        res.json({ token, user: { username: user.username, email: user.email, phone: user.phone } });
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

// إرسال رمز استعادة كلمة المرور عبر الهاتف
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { phone } = req.body;
        const user = await User.findOne({ phone: (phone || '').trim() });
        if (!user) {
            return res.status(404).json({ error: "رقم الهاتف غير مسجل لدينا" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.resetOtp = otp;
        user.resetExpires = Date.now() + 15 * 60 * 1000; // صلاحية 15 دقيقة
        await user.save();

        console.log(`[OTP] رمز التحقق لرقم ${phone} هو: ${otp}`);
        res.json({ message: "تم توليد رمز التحقق", otp });
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

// تعيين كلمة المرور الجديدة بعد التحقق من الرمز
app.post('/api/reset-password', async (req, res) => {
    try {
        const { phone, otp, newPassword } = req.body;
        const user = await User.findOne({ 
            phone: (phone || '').trim(),
            resetOtp: (otp || '').trim(),
            resetExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ error: "رمز التحقق غير صحيح أو انتهت صلاحيته" });
        }

        user.password = newPassword;
        user.resetOtp = undefined;
        user.resetExpires = undefined;
        await user.save();

        res.json({ message: "تم تغيير كلمة المرور بنجاح" });
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

// جلب إعلانات المعلن الحالي
app.get('/api/my-ads', verifyToken, async (req, res) => {
    try {
        const ads = await AdBooking.find({ 
            $or: [{ userId: req.user.id }, { name: req.user.username }]
        }).sort({ _id: -1 });
        res.json(ads);
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// مسارات تسجيل الدخول للآدمن
// ==========================================

// مسار تسجيل الدخول المباشر
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const normalizedUsername = (username || '').trim().toLowerCase();

        // تحقق مباشر للمشرف الرئيسي
        if (normalizedUsername === 'sada_admin' && password === 'Sada@2026#Secure_Pass99!') {
            const token = jwt.sign({ id: 'sada_admin_master', username: 'sada_admin', role: 'ADMIN' }, SECRET_KEY, { expiresIn: '7d' });
            return res.json({ token, username: 'sada_admin' });
        }

        const user = await User.findOne({ username: normalizedUsername });
        if (!user || password !== user.password) {
            return res.status(400).json({ error: "الاسم أو كلمة المرور غير صحيحة" });
        }

        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ token, username: user.username });
    } catch (err) {
        res.status(500).json({ error: "حدث خطأ في السيرفر" });
    }
});

// مسار التحقق من صحة توكن الآدمن
app.get('/api/verify-auth', verifyToken, (req, res) => {
    res.json({ valid: true, username: req.user.username });
});

// ==========================================
// مسارات الزيارات والمشاهدات المركزية الموحدة
// ==========================================

// مسار تسجيل زيادة زيارة حقيقية فورية (مع كل فتح أو إعادة تحميل)
app.post('/api/visit', async (req, res) => {
    try {
        const stat = await Stat.findOneAndUpdate(
            { key: 'global_visits' },
            { $inc: { visits: 1 } },
            { upsert: true, new: true }
        );
        res.json({ count: stat.visits });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار جلب إجمالي الزيارات الموحدة (محمي للآدمن فقط)
app.get('/api/visits', verifyToken, async (req, res) => {
    try {
        const stat = await Stat.findOne({ key: 'global_visits' });
        res.json({ count: stat ? stat.visits : 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار زيادة مشاهدات خبر محدد عند فتحه
app.post('/api/posts/:id/view', async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(
            req.params.id,
            { $inc: { views: 1 } },
            { new: true }
        );
        res.json({ views: post ? post.views : 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// مسارات الأخبار والإعلانات
// ==========================================

// مسار جلب الأخبار للزوار
app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ _id: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار نشر خبر جديد
app.post('/api/posts', verifyToken, async (req, res) => {
    try {
        const newPost = new Post(req.body);
        await newPost.save();
        res.json({ message: "تم النشر", post: newPost });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار تعديل خبر
app.put('/api/posts/:id', verifyToken, async (req, res) => {
    try {
        await Post.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "تم التعديل" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار حذف خبر
app.delete('/api/posts/:id', verifyToken, async (req, res) => {
    try {
        await Post.findByIdAndDelete(req.params.id);
        res.json({ message: "تم الحذف" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار استقبال طلب حجز إعلان جديد
app.post('/api/ads', async (req, res) => {
    try {
        const ad = new AdBooking(req.body);
        await ad.save();
        res.json({ message: "تم تسجيل الطلب", ad });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار جلب طلبات الإعلانات للآدمن
app.get('/api/ads', verifyToken, async (req, res) => {
    try {
        const ads = await AdBooking.find().sort({ _id: -1 });
        res.json(ads);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار موافقة الآدمن على الإعلان ونشره كخبر تلقائياً
app.put('/api/ads/:id/approve', verifyToken, async (req, res) => {
    try {
        const ad = await AdBooking.findByIdAndUpdate(req.params.id, { status: 'approved' }, { new: true });
        if (ad) {
            const newPost = new Post({
                title: `[إعلان] ${ad.title}`,
                category: 'إعلانات وترويج',
                mediaUrls: ad.imageUrl ? [ad.imageUrl] : ["https://i.postimg.cc/vBQyqJ4V/IMG-7018.png"],
                content: `${ad.content}\n\nللتواصل والاستفسار: ${ad.phone} ${ad.link ? `\nرابط المعلن: ${ad.link}` : ''}`,
                isPinned: ad.isTicker,
                status: 'published'
            });
            await newPost.save();
        }
        res.json({ message: "تمت الموافقة والنشر كخبر", ad });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار رفض طلب الإعلان
app.put('/api/ads/:id/reject', verifyToken, async (req, res) => {
    try {
        const ad = await AdBooking.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
        res.json({ message: "تم الرفض", ad });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`السيرفر يعمل الآن بنجاح على البورت ${PORT}`);
});

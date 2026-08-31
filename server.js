const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const SECRET_KEY = "Sada@Agency_Secret_Key_2026";

// الاتصال بقاعدة البيانات السحابية
mongoose.connect('mongodb+srv://sada_admin:Sada%402026%23Secure_Pass99!@cluster0.hrvqt9v.mongodb.net/sada_agency?appName=Cluster0')
  .then(async () => {
      console.log("تم الاتصال بقاعدة البيانات السحابية بنجاح");
      try {
          // تحديث أو إنشاء حساب المسؤول مباشرة لضمان مطابقة كلمة المرور
          await User.findOneAndUpdate(
              { username: "sada_admin" },
              { username: "sada_admin", password: "Sada@2026#Secure_Pass99!", role: "ADMIN" },
              { upsert: true, new: true }
          );
          console.log("تم تثبيت وتحديث حساب المشرف بنجاح (sada_admin)");
      } catch (e) {
          console.log("خطأ في تحديث الآدمن التلقائي:", e);
      }
  })
  .catch(err => console.log("خطأ في الاتصال بقاعدة البيانات:", err));

// 1. جدول المستخدمين
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'ADMIN' }
});
const User = mongoose.model('User', UserSchema);

// 2. جدول الأخبار المحدّث
const PostSchema = new mongoose.Schema({
    title: String,
    category: String,
    mediaType: String,
    mediaUrls: [String], 
    content: String,
    status: { type: String, default: 'published' },
    isPinned: { type: Boolean, default: false },
    views: { type: Number, default: 0 },
    date: { type: String, default: () => new Date().toISOString().split('T')[0] }
});
const Post = mongoose.model('Post', PostSchema);

// 3. جدول إحصائيات الزيارات الموحدة
const StatSchema = new mongoose.Schema({
    key: { type: String, default: 'global_visits' },
    visits: { type: Number, default: 0 }
});
const Stat = mongoose.model('Stat', StatSchema);

// Middleware لحماية مسارات لوحة التحكم
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "غير مصرح لك" });
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "الجلسة منتهية" });
        req.user = decoded;
        next();
    });
};

// ==========================================
// مسار تسجيل الدخول المباشر المضمون
// ==========================================
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const normalizedUsername = (username || '').trim().toLowerCase();

        // 1. تحقق مباشر لحساب المشرف الرئيسي
        if (normalizedUsername === 'sada_admin' && password === 'Sada@2026#Secure_Pass99!') {
            const token = jwt.sign({ id: 'sada_admin_master', role: 'ADMIN' }, SECRET_KEY, { expiresIn: '7d' });
            return res.json({ token, username: 'sada_admin' });
        }

        // 2. فحص قاعدة البيانات للمستخدمين الآخرين
        const user = await User.findOne({ username: normalizedUsername });
        if (!user || password !== user.password) {
            return res.status(400).json({ error: "الاسم أو كلمة المرور غير صحيحة" });
        }

        const token = jwt.sign({ id: user._id, role: user.role }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ token, username: user.username });
    } catch (err) {
        res.status(500).json({ error: "حدث خطأ في السيرفر" });
    }
});

// ==========================================
// مسارات الزيارات والمشاهدات المركزية
// ==========================================

// مسار تسجيل زيادة زيارة حقيقية
app.post('/api/visit', async (req, res) => {
    try {
        let stat = await Stat.findOne({ key: 'global_visits' });
        if (!stat) {
            stat = new Stat({ key: 'global_visits', visits: 1 });
        } else {
            stat.visits += 1;
        }
        await stat.save();
        res.json({ count: stat.visits });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار جلب إجمالي الزيارات الموحدة
app.get('/api/visits', async (req, res) => {
    try {
        const stat = await Stat.findOne({ key: 'global_visits' });
        res.json({ count: stat ? stat.visits : 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار زيادة مشاهدات خبر محدد
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
// مسارات الأخبار
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`السيرفر يعمل الآن على البورت ${PORT}`);
});

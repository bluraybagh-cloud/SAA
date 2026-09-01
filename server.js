const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const SECRET_KEY = "Sada@Agency_Secret_Key_2026";

mongoose.connect('mongodb+srv://sada_admin:Sada%402026%23Secure_Pass99!@cluster0.hrvqt9v.mongodb.net/sada_agency?appName=Cluster0')
  .then(async () => {
      console.log("تم الاتصال بقاعدة البيانات السحابية بنجاح");
      try {
          await User.findOneAndUpdate(
              { username: "sada_admin" },
              { username: "sada_admin", password: "Sada@2026#Secure_Pass99!", role: "ADMIN" },
              { upsert: true, new: true }
          );

          const existingStat = await Stat.findOne({ key: 'global_visits' });
          if (!existingStat) {
              await new Stat({ key: 'global_visits', visits: 0 }).save();
          }

          // تهيئة الحقول الثلاثة الجديدة للأخبار السابقة
          await Post.updateMany(
              { $or: [{ views: { $exists: false } }, { clicks: { $exists: false } }, { shares: { $exists: false } }] },
              { $set: { views: 0, clicks: 0, shares: 0, status: 'published', isPinned: false } }
          );
      } catch (e) {
          console.log("خطأ في التهيئة:", e);
      }
  })
  .catch(err => console.log("خطأ في الاتصال بقاعدة البيانات:", err));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'ADMIN' }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    title: String,
    category: String,
    mediaType: String,
    mediaUrls: [String], 
    content: String,
    status: { type: String, default: 'published' },
    isPinned: { type: Boolean, default: false },
    views: { type: Number, default: 0 },   // مشاهدات (المرور بالسكريل)
    clicks: { type: Number, default: 0 },  // نقرات (قراءة المزيد)
    shares: { type: Number, default: 0 },  // مشاركات السوشيال ميديا
    date: { type: String, default: () => new Date().toISOString().split('T')[0] }
});
const Post = mongoose.model('Post', PostSchema);

const StatSchema = new mongoose.Schema({
    key: { type: String, default: 'global_visits' },
    visits: { type: Number, default: 0 }
});
const Stat = mongoose.model('Stat', StatSchema);

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "غير مصرح لك" });
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "الجلسة منتهية" });
        req.user = decoded;
        next();
    });
};

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const normalizedUsername = (username || '').trim().toLowerCase();
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
        res.status(500).json({ error: "خطأ في السيرفر" });
    }
});

app.get('/api/verify-auth', verifyToken, (req, res) => {
    res.json({ valid: true, username: req.user.username });
});

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

app.get('/api/visits', verifyToken, async (req, res) => {
    try {
        const stat = await Stat.findOne({ key: 'global_visits' });
        res.json({ count: stat ? stat.visits : 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار زيادة المشاهدات (عند المرور بالسكريل)
app.post('/api/posts/:id/view', async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true });
        res.json({ views: post ? post.views : 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار زيادة النقرات (عند النقر لعرض الخبر)
app.post('/api/posts/:id/click', async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, { $inc: { clicks: 1 } }, { new: true });
        res.json({ clicks: post ? post.clicks : 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// مسار زيادة المشاركات (عند الضغط على أزرار المشاركة)
app.post('/api/posts/:id/share', async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, { $inc: { shares: 1 } }, { new: true });
        res.json({ shares: post ? post.shares : 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ _id: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/posts', verifyToken, async (req, res) => {
    try {
        const newPost = new Post(req.body);
        await newPost.save();
        res.json({ message: "تم النشر", post: newPost });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/posts/:id', verifyToken, async (req, res) => {
    try {
        await Post.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "تم التعديل" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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
    console.log(`السيرفر يعمل على البورت ${PORT}`);
});

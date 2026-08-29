const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const SECRET_KEY = "Sada@Agency_Secret_Key_2026";

// الاتصال بقاعدة البيانات السحابية مع ترميز الرموز الخاصة في كلمة المرور
mongoose.connect('mongodb+srv://bluraybagh_db_user:Sada@2026%23Secure_Pass99!@cluster0.hrvqt9v.mongodb.net/sada_agency?appName=Cluster0')
  .then(() => console.log("تم الاتصال بقاعدة البيانات السحابية بنجاح"))
  .catch(err => console.log("خطأ في الاتصال بقاعدة البيانات:", err));

// جدول المستخدمين 
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'ADMIN' }
});
const User = mongoose.model('User', UserSchema);

// جدول الأخبار 
const PostSchema = new mongoose.Schema({
    title: String,
    category: String,
    mediaType: String,
    mediaUrls: [String], 
    content: String,
    date: { type: String, default: () => new Date().toISOString().split('T')[0] }
});
const Post = mongoose.model('Post', PostSchema);

// مسار تسجيل الدخول
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user) return res.status(400).json({ error: "الاسم أو كلمة المرور غير صحيحة" });

        let isMatch = false;
        if(password === user.password) {
            isMatch = true;
        } else {
            isMatch = await bcrypt.compare(password, user.password).catch(()=>false);
        }
        
        if (!isMatch) return res.status(400).json({ error: "الاسم أو كلمة المرور غير صحيحة" });

        const token = jwt.sign({ id: user._id, role: user.role }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ token, username: user.username });
    } catch (err) {
        res.status(500).json({ error: "حدث خطأ في السيرفر" });
    }
});

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

// مسار جلب الأخبار للزوار
app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ _id: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({error: err.message});
    }
});

// مسار نشر خبر جديد 
app.post('/api/posts', verifyToken, async (req, res) => {
    try {
        const newPost = new Post(req.body);
        await newPost.save();
        res.json({ message: "تم النشر", post: newPost });
    } catch (err) {
        res.status(500).json({error: err.message});
    }
});

// مسار تعديل خبر 
app.put('/api/posts/:id', verifyToken, async (req, res) => {
    try {
        await Post.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "تم التعديل" });
    } catch (err) {
        res.status(500).json({error: err.message});
    }
});

// مسار حذف خبر 
app.delete('/api/posts/:id', verifyToken, async (req, res) => {
    try {
        await Post.findByIdAndDelete(req.params.id);
        res.json({ message: "تم الحذف" });
    } catch (err) {
        res.status(500).json({error: err.message});
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`السيرفر يعمل الآن على البورت ${PORT}`);
});

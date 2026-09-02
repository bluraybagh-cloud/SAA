const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

let bcrypt = null;
try {
    bcrypt = require('bcrypt');
} catch (e) {
    try {
        bcrypt = require('bcryptjs');
    } catch (e2) {
        bcrypt = null;
    }
}

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '30mb' }));

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "Sada@Agency_Secret_Key_2026_Secure_Token";
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://sada_admin:Sada%402026%23Secure_Pass99!@cluster0.hrvqt9v.mongodb.net/sada_agency?appName=Cluster0';

// ==========================================
// 1. تشفير كلمات المرور
// ==========================================
async function hashPassword(plainPassword) {
    if (bcrypt) {
        return await bcrypt.hash(plainPassword, 10);
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(plainPassword, salt, 1000, 64, 'sha512').toString('hex');
    return `pbkdf2:${salt}:${hash}`;
}

async function verifyPassword(plainPassword, storedPassword) {
    if (!storedPassword || !plainPassword) return false;
    if (storedPassword.startsWith('$2b$') || storedPassword.startsWith('$2a$')) {
        if (bcrypt) return await bcrypt.compare(plainPassword, storedPassword);
    }
    if (storedPassword.startsWith('pbkdf2:')) {
        const parts = storedPassword.split(':');
        const salt = parts[1];
        const originalHash = parts[2];
        const hash = crypto.pbkdf2Sync(plainPassword, salt, 1000, 64, 'sha512').toString('hex');
        return hash === originalHash;
    }
    return plainPassword === storedPassword;
}

// ==========================================
// 2. الحماية من التخمين والتكرار (Rate Limiter)
// ==========================================
const loginAttemptsMap = new Map();
const rateLimitLogin = (maxAttempts = 6, windowMs = 15 * 60 * 1000) => {
    return (req, res, next) => {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown-ip';
        const now = Date.now();
        const record = loginAttemptsMap.get(ip) || { count: 0, resetTime: now + windowMs };

        if (now > record.resetTime) {
            record.count = 0;
            record.resetTime = now + windowMs;
        }

        if (record.count >= maxAttempts) {
            const waitMinutes = Math.ceil((record.resetTime - now) / 60000);
            return res.status(429).json({ 
                error: `تم تجاوز عدد المحاولات المسموح به. يرجى الانتظار ${waitMinutes} دقيقة قبل المحاولة مجدداً.` 
            });
        }

        record.count += 1;
        loginAttemptsMap.set(ip, record);
        next();
    };
};

function clearLoginAttempts(req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown-ip';
    loginAttemptsMap.delete(ip);
}

function sanitizeInput(val) {
    if (typeof val !== 'string') return '';
    return val.trim().replace(/[$]/g, '');
}

function isValidImageString(str) {
    if (!str || typeof str !== 'string') return false;
    const isUrl = str.startsWith('http://') || str.startsWith('https://');
    const isBase64Image = str.startsWith('data:image/jpeg;base64,') || 
                          str.startsWith('data:image/jpg;base64,') || 
                          str.startsWith('data:image/png;base64,') || 
                          str.startsWith('data:image/webp;base64,') ||
                          str.startsWith('data:image/gif;base64,');
    return isUrl || isBase64Image;
}

// ==========================================
// 3. جداول قاعدة البيانات (Schemas & Models)
// ==========================================

const UserSchema = new mongoose.Schema({
    fullName: { type: String, default: '' },
    username: { type: String, required: true, unique: true, index: true },
    email: { type: String, required: true, unique: true, index: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    avatar: { type: String, default: '' },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'suspended'], default: 'pending', index: true },
    role: { type: String, enum: ['ADMIN', 'ADVERTISER', 'USER'], default: 'USER' }
}, { timestamps: true });

UserSchema.set('toJSON', {
    transform: (doc, ret) => {
        delete ret.password;
        return ret;
    }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    title: { type: String, required: true },
    category: { type: String, default: 'عام' },
    mediaType: { type: String, default: 'image' },
    mediaUrls: [String], 
    content: { type: String, required: true },
    status: { type: String, enum: ['published', 'draft'], default: 'published' },
    isPinned: { type: Boolean, default: false },
    views: { type: Number, default: 0 },
    shares: { type: Number, default: 0 },
    likesCount: { type: Number, default: 0 },
    dislikesCount: { type: Number, default: 0 },
    commentsCount: { type: Number, default: 0 },
    date: { type: String, default: () => new Date().toISOString().split('T')[0] }
}, { timestamps: true });
const Post = mongoose.model('Post', PostSchema);

const ReactionSchema = new mongoose.Schema({
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, enum: ['like', 'dislike'], required: true }
}, { timestamps: true });
ReactionSchema.index({ postId: 1, userId: 1 }, { unique: true });
const Reaction = mongoose.model('Reaction', ReactionSchema);

const CommentSchema = new mongoose.Schema({
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    userAvatar: { type: String, default: '' },
    content: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending', index: true },
    date: { type: String, default: () => new Date().toISOString() }
}, { timestamps: true });
const Comment = mongoose.model('Comment', CommentSchema);

const StatSchema = new mongoose.Schema({
    key: { type: String, default: 'global_visits', unique: true },
    visits: { type: Number, default: 0 }
});
const Stat = mongoose.model('Stat', StatSchema);

const AdBookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    orderId: { type: String, index: true },
    name: String,
    phone: String,
    email: String,
    title: String,
    content: String,
    link: String,
    package: String,
    isTicker: { type: Boolean, default: false },
    totalPrice: { type: Number, default: 0 },
    imageUrl: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    rejectReason: { type: String, default: '' },
    date: { type: String, default: () => new Date().toISOString().split('T')[0] }
}, { timestamps: true });
const AdBooking = mongoose.model('AdBooking', AdBookingSchema);

// ==========================================
// 4. الاتصال والتهيئة
// ==========================================
mongoose.connect(MONGODB_URI)
  .then(async () => {
      console.log("تم الاتصال بقاعدة البيانات السحابية بنجاح وبأمان.");
      try {
          const adminUsername = "sada_admin";
          const adminPasswordRaw = "Sada@2026#Secure_Pass99!";
          const existingAdmin = await User.findOne({ username: adminUsername });

          if (!existingAdmin) {
              const secureHashedPassword = await hashPassword(adminPasswordRaw);
              await new User({
                  fullName: "مشرف الوكالة الرئيسي",
                  username: adminUsername,
                  email: "admin@sadaalataa.com",
                  phone: "07827992437",
                  password: secureHashedPassword,
                  status: "approved",
                  role: "ADMIN"
              }).save();
          }

          const existingStat = await Stat.findOne({ key: 'global_visits' });
          if (!existingStat) {
              await new Stat({ key: 'global_visits', visits: 0 }).save();
          }

          await Post.updateMany(
              { views: { $exists: false } },
              { $set: { views: 0, shares: 0, likesCount: 0, dislikesCount: 0, commentsCount: 0, status: 'published', isPinned: false } }
          );
      } catch (e) {
          console.error("تنبيه تهيئة:", e.message);
      }
  })
  .catch(err => console.error("خطأ اتصال مونغو:", err.message));

// ==========================================
// 5. الصلاحيات والـ Middlewares
// ==========================================

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "جلسة غير مصرح بها. يرجى تسجيل الدخول" });

    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً" });
        req.user = decoded;
        next();
    });
};

const verifyActiveUser = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user && req.user.status === 'approved') {
            next();
        } else {
            return res.status(403).json({ 
                error: "يتطلب التفاعل أو التعليق حساباً نشطاً ومقبولاً من قبل إدارة الموقع." 
            });
        }
    });
};

const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user && req.user.role === 'ADMIN') {
            next();
        } else {
            return res.status(403).json({ error: "وصول محظور: يتطلب صلاحيات إدارة النظام" });
        }
    });
};

// ==========================================
// 6. مسارات حسابات المستخدمين والبروفايل
// ==========================================

app.post('/api/user/register', rateLimitLogin(5, 10 * 60 * 1000), async (req, res) => {
    try {
        const fullName = sanitizeInput(req.body.fullName);
        const username = sanitizeInput(req.body.username).toLowerCase();
        const email = sanitizeInput(req.body.email).toLowerCase();
        const phone = sanitizeInput(req.body.phone);
        const password = typeof req.body.password === 'string' ? req.body.password : '';
        const confirmPassword = typeof req.body.confirmPassword === 'string' ? req.body.confirmPassword : '';

        if (!fullName || !username || !email || !password) {
            return res.status(400).json({ error: "يرجى تعبئة جميع الحقول المطلوبة" });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: "يجب ألا تقل كلمة المرور عن 6 أحرف" });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ error: "كلمتا المرور غير متطابقتين" });
        }

        const existing = await User.findOne({ 
            $or: [{ username }, { email }] 
        });
        if (existing) {
            return res.status(400).json({ error: "اسم المستخدم أو البريد الإلكتروني مسجل مسبقاً" });
        }

        const securePassword = await hashPassword(password);
        const newUser = new User({
            fullName,
            username,
            email,
            phone,
            password: securePassword,
            status: 'pending',
            role: 'USER'
        });
        await newUser.save();

        clearLoginAttempts(req);
        res.json({ 
            message: "تم تسجيل الحساب بنجاح! حسابك الآن قيد مراجعة وتدقيق الإدارة وسيتم تفعيله قريباً.",
            status: 'pending'
        });
    } catch (err) {
        res.status(500).json({ error: "تعذر إكمال طلب التسجيل، يرجى المحاولة لاحقاً" });
    }
});

app.post('/api/user/login', rateLimitLogin(6, 15 * 60 * 1000), async (req, res) => {
    try {
        const searchKey = sanitizeInput(req.body.usernameOrEmail).toLowerCase();
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        if (!searchKey || !password) {
            return res.status(400).json({ error: "يرجى إدخال اسم المستخدم وكلمة المرور" });
        }

        const user = await User.findOne({
            $or: [{ username: searchKey }, { email: searchKey }]
        });

        if (!user) {
            return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });
        }

        const isPasswordCorrect = await verifyPassword(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });
        }

        if (user.status === 'pending') {
            return res.status(403).json({ 
                error: "حسابك قيد المراجعة والتدقيق من قبل الإدارة، يرجى الانتظار حتى يتم اعتماده وتفعيله",
                status: 'pending'
            });
        }
        if (user.status === 'rejected') {
            return res.status(403).json({ 
                error: "تم رفض طلب إنشاء هذا الحساب من قبل إدارة الموقع",
                status: 'rejected'
            });
        }
        if (user.status === 'suspended') {
            return res.status(403).json({ 
                error: "تم إيقاف هذا الحساب مؤقتاً من قبل الإدارة",
                status: 'suspended'
            });
        }

        clearLoginAttempts(req);
        const token = jwt.sign(
            { id: user._id, username: user.username, email: user.email, role: user.role, status: user.status }, 
            SECRET_KEY, 
            { expiresIn: '15d' }
        );

        res.json({ 
            token, 
            user: { 
                id: user._id, 
                fullName: user.fullName, 
                username: user.username, 
                email: user.email, 
                phone: user.phone,
                avatar: user.avatar,
                status: user.status,
                role: user.role
            } 
        });
    } catch (err) {
        res.status(500).json({ error: "تعذر تسجيل الدخول حالياً" });
    }
});

app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -__v');
        if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: "تعذر جلب بيانات البروفايل" });
    }
});

app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { fullName, phone, currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });

        if (fullName) user.fullName = sanitizeInput(fullName);
        if (phone) user.phone = sanitizeInput(phone);

        if (newPassword && newPassword.length >= 6) {
            if (!currentPassword) {
                return res.status(400).json({ error: "يرجى إدخال كلمة المرور الحالية لتغيير كلمة المرور" });
            }
            const isMatch = await verifyPassword(currentPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ error: "كلمة المرور الحالية غير صحيحة" });
            }
            user.password = await hashPassword(newPassword);
        }

        await user.save();
        res.json({ message: "تم تحديث البيانات بنجاح", user });
    } catch (err) {
        res.status(500).json({ error: "تعذر تعديل البيانات" });
    }
});

app.post('/api/user/avatar', verifyToken, async (req, res) => {
    try {
        const { avatar } = req.body;
        if (!avatar || !isValidImageString(avatar)) {
            return res.status(400).json({ error: "صيغة الصورة غير صالحة" });
        }

        const user = await User.findByIdAndUpdate(
            req.user.id, 
            { avatar }, 
            { new: true }
        ).select('-password');

        res.json({ message: "تم تحديث الصورة الشخصية بنجاح", avatar: user.avatar });
    } catch (err) {
        res.status(500).json({ error: "تعذر حفظ الصورة الشخصية" });
    }
});

app.delete('/api/user/avatar', verifyToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { avatar: '' });
        res.json({ message: "تم حذف الصورة الشخصية بنجاح" });
    } catch (err) {
        res.status(500).json({ error: "تعذر حذف الصورة" });
    }
});

// ==========================================
// 7. مسارات المعلنين وحجز الإعلانات
// ==========================================

app.post('/api/register', rateLimitLogin(5, 10 * 60 * 1000), async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username).toLowerCase();
        const email = sanitizeInput(req.body.email).toLowerCase();
        const phone = sanitizeInput(req.body.phone);
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        if (!username || !email || !password || password.length < 6) {
            return res.status(400).json({ error: "يرجى ملء جميع الحقول المطلوبة" });
        }

        const existing = await User.findOne({ 
            $or: [{ username }, { email }] 
        });
        if (existing) {
            return res.status(400).json({ error: "اسم المستخدم أو البريد مسجل مسبقاً" });
        }

        const securePassword = await hashPassword(password);
        const newUser = new User({
            username,
            email,
            phone,
            password: securePassword,
            status: 'approved',
            role: 'ADVERTISER'
        });
        await newUser.save();

        clearLoginAttempts(req);
        const token = jwt.sign(
            { id: newUser._id, username: newUser.username, email: newUser.email, role: newUser.role, status: newUser.status }, 
            SECRET_KEY, 
            { expiresIn: '15d' }
        );

        res.json({ 
            token, 
            user: { id: newUser._id, username: newUser.username, email: newUser.email, phone: newUser.phone } 
        });
    } catch (err) {
        res.status(500).json({ error: "تعذر إكمال التسجيل" });
    }
});

app.post('/api/advertiser/login', rateLimitLogin(6, 15 * 60 * 1000), async (req, res) => {
    try {
        const searchKey = sanitizeInput(req.body.usernameOrEmail).toLowerCase();
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        const user = await User.findOne({
            $or: [{ username: searchKey }, { email: searchKey }]
        });

        if (!user) return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });

        const isPasswordCorrect = await verifyPassword(password, user.password);
        if (!isPasswordCorrect) return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });

        clearLoginAttempts(req);
        const token = jwt.sign(
            { id: user._id, username: user.username, email: user.email, role: user.role, status: user.status }, 
            SECRET_KEY, 
            { expiresIn: '15d' }
        );

        res.json({ 
            token, 
            user: { id: user._id, username: user.username, email: user.email, phone: user.phone } 
        });
    } catch (err) {
        res.status(500).json({ error: "تعذر تسجيل الدخول" });
    }
});

app.get('/api/my-ads', verifyToken, async (req, res) => {
    try {
        const ads = await AdBooking.find({ 
            $or: [
                { userId: req.user.id },
                { name: req.user.username },
                { email: req.user.email }
            ]
        }).sort({ _id: -1 }).select('-__v');
        res.json(ads);
    } catch (err) {
        res.status(500).json({ error: "تعذر جلب الإعلانات" });
    }
});

app.post('/api/ads', async (req, res) => {
    try {
        const adData = req.body;
        if (!adData.title || !adData.content || !adData.name) {
            return res.status(400).json({ error: "يرجى إكمال بيانات الإعلان الأساسية" });
        }
        if (adData.imageUrl && !isValidImageString(adData.imageUrl)) {
            adData.imageUrl = '';
        }

        const token = req.headers['authorization'];
        if (token) {
            try {
                const cleanToken = token.startsWith('Bearer ') ? token.slice(7) : token;
                const decoded = jwt.verify(cleanToken, SECRET_KEY);
                adData.userId = decoded.id;
            } catch (e) {}
        }

        adData.title = sanitizeInput(adData.title);
        adData.content = sanitizeInput(adData.content);
        adData.name = sanitizeInput(adData.name);
        adData.status = 'pending';
        adData.rejectReason = '';

        const ad = new AdBooking(adData);
        await ad.save();
        res.json({ message: "تم تسجيل طلب الإعلان بنجاح", ad });
    } catch (err) {
        res.status(500).json({ error: "تعذر إرسال طلب الإعلان" });
    }
});

app.get('/api/ads', verifyAdmin, async (req, res) => {
    try {
        const ads = await AdBooking.find().sort({ _id: -1 }).select('-__v');
        res.json(ads);
    } catch (err) {
        res.status(500).json({ error: "تعذر جلب طلبات الإعلانات" });
    }
});

app.put('/api/ads/:id/approve', verifyAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "معرف غير صالح" });
        }
        const ad = await AdBooking.findByIdAndUpdate(req.params.id, { status: 'approved' }, { new: true });
        if (ad) {
            const newPost = new Post({
                title: `[إعلان] ${ad.title}`,
                category: 'إعلانات وترويج',
                mediaUrls: (ad.imageUrl && isValidImageString(ad.imageUrl)) ? [ad.imageUrl] : ["https://i.postimg.cc/pTtr2cpX/IMG-6997.jpg"],
                content: `${ad.content}\n\nللتواصل والاستفسار: ${ad.phone} ${ad.link ? `\nرابط المعلن: ${ad.link}` : ''}`,
                isPinned: Boolean(ad.isTicker),
                status: 'published'
            });
            await newPost.save();
        }
        res.json({ message: "تمت الموافقة ونشر الإعلان", ad });
    } catch (err) {
        res.status(500).json({ error: "تعذر إتمام الموافقة" });
    }
});

app.put('/api/ads/:id/reject', verifyAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "معرف غير صالح" });
        }
        const rejectReason = sanitizeInput(req.body.rejectReason) || 'لم يتم استيفاء شروط وضوابط النشر المعتمدة';
        const ad = await AdBooking.findByIdAndUpdate(
            req.params.id, 
            { status: 'rejected', rejectReason }, 
            { new: true }
        );
        res.json({ message: "تم رفض الطلب وتسجيل السبب للمعلن", ad });
    } catch (err) {
        res.status(500).json({ error: "تعذر إتمام الرفض" });
    }
});

// ==========================================
// 8. مسارات دخول المشرف والتحقق
// ==========================================

app.post('/api/login', rateLimitLogin(5, 15 * 60 * 1000), async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username).toLowerCase();
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        const user = await User.findOne({ username, role: 'ADMIN' });
        if (!user) return res.status(400).json({ error: "الاسم أو كلمة المرور غير صحيحة" });

        const isMatch = await verifyPassword(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "الاسم أو كلمة المرور غير صحيحة" });

        clearLoginAttempts(req);
        const token = jwt.sign(
            { id: user._id, username: user.username, role: 'ADMIN', status: user.status }, 
            SECRET_KEY, 
            { expiresIn: '7d' }
        );

        res.json({ token, username: user.username });
    } catch (err) {
        res.status(500).json({ error: "حدث خطأ غير متوقع في الخادم" });
    }
});

app.get('/api/verify-auth', verifyAdmin, (req, res) => {
    res.json({ valid: true, username: req.user.username, role: req.user.role });
});

// ==========================================
// 9. مسارات الزيارات والمشاهدات والمشاركات
// ==========================================

app.post('/api/visit', async (req, res) => {
    try {
        const stat = await Stat.findOneAndUpdate(
            { key: 'global_visits' },
            { $inc: { visits: 1 } },
            { upsert: true, new: true }
        );
        res.json({ count: stat.visits });
    } catch (err) {
        res.status(500).json({ error: "تعذر تسجيل الزيارة" });
    }
});

app.get('/api/visits', verifyAdmin, async (req, res) => {
    try {
        const stat = await Stat.findOne({ key: 'global_visits' });
        res.json({ count: stat ? stat.visits : 0 });
    } catch (err) {
        res.status(500).json({ error: "تعذر جلب الزيارات" });
    }
});

app.post('/api/posts/:id/view', async (req, res) => {
    try {
        const postId = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(postId)) return res.json({ views: 0 });
        const post = await Post.findByIdAndUpdate(
            postId,
            { $inc: { views: 1 } },
            { new: true }
        );
        res.json({ views: post ? (post.views || 1) : 1 });
    } catch (err) {
        res.json({ views: 1 });
    }
});

app.post('/api/posts/:id/share', async (req, res) => {
    try {
        const postId = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(postId)) return res.json({ shares: 0 });
        const post = await Post.findByIdAndUpdate(
            postId,
            { $inc: { shares: 1 } },
            { new: true }
        );
        res.json({ shares: post ? (post.shares || 1) : 1 });
    } catch (err) {
        res.json({ shares: 1 });
    }
});

// ==========================================
// 10. مسارات التفاعل والتعليقات على الأخبار
// ==========================================

app.post('/api/posts/:id/react', verifyActiveUser, async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user.id;
        const { type } = req.body;

        if (!['like', 'dislike'].includes(type)) {
            return res.status(400).json({ error: "نوع التفاعل غير صالح" });
        }

        const existing = await Reaction.findOne({ postId, userId });
        let userReaction = null;

        if (existing) {
            if (existing.type === type) {
                await Reaction.findByIdAndDelete(existing._id);
                userReaction = null;
            } else {
                existing.type = type;
                await existing.save();
                userReaction = type;
            }
        } else {
            await new Reaction({ postId, userId, type }).save();
            userReaction = type;
        }

        const likesCount = await Reaction.countDocuments({ postId, type: 'like' });
        const dislikesCount = await Reaction.countDocuments({ postId, type: 'dislike' });

        await Post.findByIdAndUpdate(postId, { likesCount, dislikesCount });

        res.json({ userReaction, likesCount, dislikesCount });
    } catch (err) {
        res.status(500).json({ error: "تعذر تسجيل التفاعل" });
    }
});

app.get('/api/posts/:id/comments', async (req, res) => {
    try {
        const postId = req.params.id;
        const comments = await Comment.find({ postId, status: 'approved' })
            .sort({ _id: -1 })
            .select('userName userAvatar content date createdAt');
        res.json(comments);
    } catch (err) {
        res.status(500).json({ error: "تعذر جلب التعليقات" });
    }
});

app.post('/api/posts/:id/comments', verifyActiveUser, async (req, res) => {
    try {
        const postId = req.params.id;
        const content = sanitizeInput(req.body.content);

        if (!content || content.length < 2) {
            return res.status(400).json({ error: "يرجى كتابة نص التعليق" });
        }

        const user = await User.findById(req.user.id);
        const newComment = new Comment({
            postId,
            userId: req.user.id,
            userName: user.fullName || user.username,
            userAvatar: user.avatar || '',
            content,
            status: 'pending'
        });
        await newComment.save();

        res.json({ 
            message: "تم إرسال تعليقك بنجاح وهو الآن قيد مراجعة الإدارة قبل النشر.",
            comment: newComment 
        });
    } catch (err) {
        res.status(500).json({ error: "تعذر إرسال التعليق" });
    }
});

// ==========================================
// 11. مسارات لوحة تحكم الأدمن للمستخدمين والتعليقات والأخبار
// ==========================================

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ _id: -1 }).select('-__v');
        res.json(posts || []);
    } catch (err) {
        res.status(500).json({ error: "تعذر جلب الأخبار" });
    }
});

app.post('/api/posts', verifyAdmin, async (req, res) => {
    try {
        const { title, category, mediaUrls, content, isPinned, status, date } = req.body;
        if (!title || !content) return res.status(400).json({ error: "العنوان والمحتوى حقول إجبارية" });

        const safeUrls = Array.isArray(mediaUrls) 
            ? mediaUrls.filter(u => isValidImageString(u))
            : ["https://i.postimg.cc/pTtr2cpX/IMG-6997.jpg"];

        const newPost = new Post({
            title: sanitizeInput(title),
            category: sanitizeInput(category) || 'عام',
            mediaUrls: safeUrls.length > 0 ? safeUrls : ["https://i.postimg.cc/pTtr2cpX/IMG-6997.jpg"],
            content: sanitizeInput(content),
            isPinned: Boolean(isPinned),
            status: status === 'draft' ? 'draft' : 'published',
            date: date || new Date().toISOString().split('T')[0]
        });

        await newPost.save();
        res.json({ message: "تم نشر الخبر بنجاح", post: newPost });
    } catch (err) {
        res.status(500).json({ error: "تعذر نشر الخبر" });
    }
});

app.put('/api/posts/:id', verifyAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "معرف غير صالح" });
        const updateData = { ...req.body };
        if (updateData.title) updateData.title = sanitizeInput(updateData.title);
        if (updateData.content) updateData.content = sanitizeInput(updateData.content);

        await Post.findByIdAndUpdate(req.params.id, updateData);
        res.json({ message: "تم التعديل بنجاح" });
    } catch (err) {
        res.status(500).json({ error: "تعذر تعديل الخبر" });
    }
});

app.delete('/api/posts/:id', verifyAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "معرف غير صالح" });
        await Post.findByIdAndDelete(req.params.id);
        res.json({ message: "تم الحذف بنجاح" });
    } catch (err) {
        res.status(500).json({ error: "تعذر حذف الخبر" });
    }
});

app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const users = await User.find().sort({ _id: -1 }).select('-password -__v');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: "تعذر جلب قائمة المستخدمين" });
    }
});

app.put('/api/admin/users/:id/status', verifyAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        if (!['pending', 'approved', 'rejected', 'suspended'].includes(status)) {
            return res.status(400).json({ error: "حالة غير صالحة" });
        }
        const user = await User.findByIdAndUpdate(req.params.id, { status }, { new: true }).select('-password');
        res.json({ message: "تم تحديث حالة المستخدم بنجاح", user });
    } catch (err) {
        res.status(500).json({ error: "تعذر تحديث حالة المستخدم" });
    }
});

app.get('/api/admin/comments', verifyAdmin, async (req, res) => {
    try {
        const comments = await Comment.find().sort({ _id: -1 }).populate('postId', 'title');
        res.json(comments);
    } catch (err) {
        res.status(500).json({ error: "تعذر جلب التعليقات للإدارة" });
    }
});

app.put('/api/admin/comments/:id/status', verifyAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        if (!['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: "حالة غير صالحة" });
        }
        const comment = await Comment.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (comment) {
            const approvedCount = await Comment.countDocuments({ postId: comment.postId, status: 'approved' });
            await Post.findByIdAndUpdate(comment.postId, { commentsCount: approvedCount });
        }
        res.json({ message: "تم تحديث حالة التعليق بنجاح", comment });
    } catch (err) {
        res.status(500).json({ error: "تعذر تحديث حالة التعليق" });
    }
});

app.delete('/api/admin/comments/:id', verifyAdmin, async (req, res) => {
    try {
        const comment = await Comment.findByIdAndDelete(req.params.id);
        if (comment) {
            const approvedCount = await Comment.countDocuments({ postId: comment.postId, status: 'approved' });
            await Post.findByIdAndUpdate(comment.postId, { commentsCount: approvedCount });
        }
        res.json({ message: "تم حذف التعليق بنجاح" });
    } catch (err) {
        res.status(500).json({ error: "تعذر حذف التعليق" });
    }
});
// حذف مستخدم نهائياً من قبل الأدمن
app.delete('/api/admin/users/:id', verifyAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "معرف المستخدم غير صالح" });
        }
        const user = await User.findById(req.params.id);
        if (user && user.role === 'ADMIN') {
            return res.status(400).json({ error: "لا يمكن حذف حساب المشرف الرئيسي" });
        }
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: "تم حذف المستخدم بنجاح" });
    } catch (err) {
        res.status(500).json({ error: "تعذر حذف المستخدم" });
    }
});
app.listen(PORT, () => {
    console.log(`السيرفر يعمل الآن بأمان كامل على المنفذ ${PORT}`);
});

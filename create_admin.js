const mongoose = require('mongoose');

// رابط قاعدة البيانات الخاص بك مع ترميز كلمة المرور
const MONGO_URI = 'mongodb+srv://bluraybagh_db_user:Sada@2026%23Secure_Pass99!@cluster0.hrvqt9v.mongodb.net/sada_agency?appName=Cluster0';

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'ADMIN' }
});
const User = mongoose.model('User', UserSchema);

async function createAdmin() {
    try {
        await mongoose.connect(MONGO_URI);
        console.log("تم الاتصال بقاعدة البيانات...");

        // بيانات حساب المشرف الجديد
        const username = "admin";
        const password = "adminpassword123"; // هذه كلمة المرور المؤقتة

        // التحقق هل الحساب موجود مسبقاً
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            console.log("حساب المشرف موجود مسبقاً بالفعل!");
        } else {
            const newUser = new User({ username, password });
            await newUser.save();
            console.log("تم إنشاء حساب المشرف بنجاح تام!");
        }
        process.exit(0);
    } catch (err) {
        console.error("حدث خطأ:", err);
        process.exit(1);
    }
}

createAdmin();

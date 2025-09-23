// ------------------ 1. 引入所需的库 ------------------
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 创建一个Express应用
const app = express();
// 设置端口号，如果环境变量有则用环境的，没有就用3000
const PORT = process.env.PORT || 3000;

// ------------------ 2. 中间件设置 ------------------
// 这个中间件用于解析JSON格式的请求体（POST请求传来的JSON数据）
app.use(express.json());

// ------------------ 3. 连接MongoDB数据库 ------------------
// ！！！重要：替换为你自己的MongoDB连接字符串！！！
const YOUR_MONGODB_CONNECTION_STRING = "mongodb+srv://506424912_db_user:ICY0tGzPAzGo2A12@cluster0.yfetnnh.mongodb.net/myWebsite?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(YOUR_MONGODB_CONNECTION_STRING)
  .then(() => console.log('成功连接到MongoDB数据库!'))
  .catch(error => console.error('连接数据库失败:', error));

// ------------------ 4. 定义数据模型（用户模型） ------------------
// 这相当于定义了一个Excel表的结构：表名叫User，里面有username和password两列
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true }, // 用户名，必填，且不能重复
  password: { type: String, required: true } // 密码，必填
});

// 创建User模型
const User = mongoose.model('User', UserSchema);

// ------------------ 5. 注册接口 /api/register ------------------
// 当客户端POST请求到 /api/register 时，这个函数被执行
app.post('/api/register', async (req, res) => {
  try {
    // 1. 从请求体中获取用户名和密码
    const { username, password } = req.body;

    // 2. 检查用户是否已存在
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: '用户名已存在' });
    }

    // 3. 加密密码（绝对不要明文存储密码！）
    // 10是加密强度，数字越大越安全但也越慢
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. 创建新用户并保存到数据库
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    // 5. 返回成功消息
    res.status(201).json({ message: '用户注册成功！' });

  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ message: '服务器内部错误' });
  }
});

// ------------------ 6. 登录接口 /api/login ------------------
app.post('/api/login', async (req, res) => {
  try {
    // 1. 从请求体中获取用户名和密码
    const { username, password } = req.body;

    // 2. 查找用户是否存在
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: '用户名或密码错误' });
    }

    // 3. 比较密码是否匹配
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: '用户名或密码错误' });
    }

    // 4. 生成一个Token（令牌），用于后续的身份验证
    // 这就像是一张门禁卡，登录后发给用户，之后用户拿着卡就可以访问需要权限的接口
    // 'yourSecretKey'是你的密钥，应该用更复杂的字符串，且不要泄露
    const token = jwt.sign({ userId: user._id }, 'yourSecretKey', { expiresIn: '1h' });

    // 5. 返回登录成功信息和Token
    res.json({ 
      message: '登录成功！', 
      token: token,
      username: username 
    });

  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ message: '服务器内部错误' });
  }
});

// ------------------ 7. 启动服务器 ------------------
app.listen(PORT, () => {
  console.log(`服务器正在运行在 http://localhost:${PORT}`);
});
const catchError = require("../utils/catchError");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");
const jwt = require("jsonwebtoken");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({
    email,
    password: hashedPassword,
    firstName,
    lastName,
    country,
    image,
    frontBaseUrl,
  });
  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/verify_email/${code}`;
  await sendEmail({
    to: email,
    subject: "Verificate Email for user app",
    html: `
        <h1>Hello ${firstName} ${lastName}</h1>
        <b>Verify your account clicking this link </b>
        <a href="${link}">${link}</a>
        <p>Thank you</p>

    `,
  });
  await EmailCode.create({ code, userId: user.id });
  return res.status(201).json(user);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.update(req.body, {
    where: { id },
    returning: true,
  });
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

// verificar código enviado por Email
const verifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const codeFound = await EmailCode.findOne({ where: { code } });
  if (!codeFound) return res.status(401).json({ massege: "Invalid code" });
  const user = await User.update(
    { isVerified: true },
    { where: { id: codeFound.userId }, returning: true }
  );
  await codeFound.destroy();
  res.json(user);
});

// login con bcrypt y JWT
const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ error: "invalid credentials" });
  if (!user.isVerified)
    return res.status(401).json({ massege: "user not verified" });

  const token = jwt.sign(
    { user },
    process.env.TOKEN_SECRET
    // { expiresIn: '1d' }
  );

  return res.json({ user, token });
});

// Obtener el usuario logeado
const getLoggedUser = catchError(async (req, res) => {
  const user = req.user;
  res.json(user);
});

// Reestablecer contraseña
const passwordReset = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/reset_password/${code}`;
  await sendEmail({
    to: email,
    subject: "Password recovery",
    html: `
        <h1>Hello ${user.firstName} ${user.lastName}</h1>
        <b>To recover your password, click on the following link</b>
        <a href="${link}">${link}</a>
        <p>Thank you!</p>

    `,
  });
  await EmailCode.create({ code, userId: user.id });
  return res.status(201).json(user);
});

// Validar código enviado para recuperar contraseña
const verifyRecoveryCode = catchError(async (req, res) => {
  const { code } = req.params;
  const { password } = req.body;
  const codeFound = await EmailCode.findOne({ where: { code } });
  if (!codeFound) return res.status(401).json({ massege: "Invalid code" });
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.update(
    { password: hashedPassword },
    { where: { id: codeFound.userId }, returning: true }
  );
  await codeFound.destroy();
  res.json(user);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyCode,
  login,
  getLoggedUser,
  passwordReset,
  verifyRecoveryCode,
};

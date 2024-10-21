const connection = require("../config/database");
const jwt = require("jsonwebtoken");

const login = (req, res) => {
  const { username, password } = req.body;

  // Validasi input
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  // Mendapatkan kunci enkripsi dan JWT secret dari environment variables
  const userKey = process.env.ENCRYPTION_KEY_USER;
  const passwordKey = process.env.ENCRYPTION_KEY_PASSWORD;
  const jwtSecretKey = process.env.ACCESS_TOKEN_SECRET;

  // SQL query dengan parameter yang aman untuk menghindari SQL Injection
  const sql = `
    SELECT AES_DECRYPT(u.id_user, ?) AS decryptedUser, AES_DECRYPT(u.password, ?) AS decryptedPassword, p.nama 
    FROM user u 
    JOIN pegawai p ON AES_DECRYPT(u.id_user, ?) = p.nik
    WHERE AES_DECRYPT(u.id_user, ?) = ?
  `;

  // Eksekusi query ke database
  connection.query(
    sql,
    [userKey, passwordKey, userKey, userKey, username],
    (err, results) => {
      if (err) {
        console.error("Database query error:", err);
        return res
          .status(500)
          .json({ message: "Internal server error", error: err });
      }

      // Cek apakah user ditemukan
      if (results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const user = results[0];

      // Cek apakah password berhasil didekripsi
      if (user.decryptedPassword === null) {
        return res.status(500).json({ message: "Error decrypting password" });
      }

      // Validasi password
      if (password === user.decryptedPassword.toString()) {
        // Buat token JWT
        const token = jwt.sign(
          { id: user.decryptedUser, name: user.nama },
          jwtSecretKey,
          { expiresIn: "1h" }
        );

        // Kirim token melalui cookie yang aman
        res.cookie("token", token, {
          httpOnly: true, // Mencegah akses melalui JavaScript di browser
          secure: process.env.NODE_ENV === "production", // Cookie hanya dikirim melalui HTTPS di production
          maxAge: 3600000, // 1 jam
        });

        return res.status(200).json({ message: "Login successful", token });
      } else {
        return res.status(401).json({ message: "Incorrect password" });
      }
    }
  );
};

module.exports = {
  login,
};

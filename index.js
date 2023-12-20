const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { google } = require("googleapis");

const app = express();
const PORT = 5000;
const prisma = new PrismaClient();

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  "http://localhost:5000/auth/google/callback"
);

const scopes = [
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
];

const authorizationUrl = oauth2Client.generateAuthUrl({
  access_type: "offline",
  scope: scopes,
  include_granted_scopes: true,
});

app.use(express.json());

const accessValidation = (req, res, next) => {
  const { authorization } = req.headers;

  console.log("Authorization Header:", authorization);

  if (!authorization) {
    return res.status(401).json({
      message: "Token diperlukan",
    });
  }

  const token = authorization.split(" ")[1];
  const secret = process.env.JWT_SECRET;

  console.log("Extracted Token:", token);

  try {
    const jwtDecode = jwt.verify(token, secret);

    if (typeof jwtDecode !== "string") {
      req.userData = jwtDecode;
    }
    console.log("Decoded JWT:", jwtDecode);
  } catch (error) {
    console.error("Error verifying token:", error);
    return res.status(401).json({
      message: "Unauthorized",
    });
  }
  next();
};

app.get("/auth/google", (req, res) => {
  res.redirect(authorizationUrl);
});

app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;

  const { tokens } = await oauth2Client.getToken(code);

  oauth2Client.setCredentials(tokens);

  const oauth2 = google.oauth2({
    auth: oauth2Client,
    version: "v2",
  });

  const { data } = await oauth2.userinfo.get();

  if (!data.email || !data.name) {
    return res.json({
      data: data,
    });
  }

  let user = await prisma.users.findUnique({
    where: {
      email: data.email,
    },
  });

  if (!user) {
    user = await prisma.users.create({
      data: {
        name: data.name,
        email: data.email,
      },
    });
  }

  const payload = {
    id: user.id,
    name: user.name,
  };

  const secret = process.env.JWT_SECRET;

  const expiresIn = 60 * 60 * 1;

  const token = jwt.sign(payload, secret, { expiresIn: expiresIn });

  return res.json({
    data: {
      id: user.id,
      name: user.name,
      token: token,
    },
  });
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: "Name, email, and password are required fields" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await prisma.users.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    res.json({
      message: "User created successfully",
      user: result,
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    const user = await prisma.users.findUnique({
      where: {
        email: email,
      },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (!user.password) {
      return res.status(404).json({
        message: "Password not set",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      const payload = {
        id: user.id,
        name: user.name,
        email: user.email,
      };

      const secret = process.env.JWT_SECRET || "your-secret-key";
      const expiresIn = 60 * 60 * 1;

      const token = jwt.sign(payload, secret, { expiresIn: expiresIn });

      return res.json({
        data: {
          id: user.id,
          name: user.name,
          email: user.email,
          token: token,
        },
      });
    } else {
      return res.status(403).json({
        message: "Wrong password",
      });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.post("/users/validations", accessValidation, async (req, res, next) => {
  const { name, email } = req.body;

  const result = await prisma.users.create({
    data: {
      name: name,
      email: email,
    },
  });
  res.json({
    data: result,
    message: `User created`,
  });
});

app.get("/users", async (req, res) => {
  const result = await prisma.users.findMany({
    select: {
      id: true,
      name: true,
      email: true,
    },
  });
  res.json({
    data: result,
    message: "User list",
  });
});

app.get("/users/:id", async (req, res) => {
  const userId = parseInt(req.params.id);

  try {
    const user = await prisma.users.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
      },
    });

    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    res.json({
      data: user,
      message: "User details",
    });
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/users", accessValidation, async (req, res) => {
  const result = await prisma.users.findMany({
    select: {
      id: true,
      name: true,
      email: true,
    },
  });
  res.json({
    data: result,
    message: "User list",
  });
});

app.patch("/users/:id", accessValidation, async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;

  const result = await prisma.users.update({
    data: {
      name: name,
      email: email,
    },
    where: {
      id: Number(id),
    },
  });
  res.json({
    data: result,
    message: `User ${id} updated`,
  });
});

app.delete("/users/:id", accessValidation, async (req, res) => {
  const { id } = req.params;

  const result = await prisma.users.delete({
    where: {
      id: Number(id),
    },
  });
  res.json({
    message: `User ${id} deleted`,
  });
});

app.listen(PORT, () => {
  console.log(`Server running in PORT: ${PORT}`);
});

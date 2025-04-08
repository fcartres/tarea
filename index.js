import express from "express";
import crypto from "node:crypto";


const PORT = process.env.PORT ?? 3000;

const app = express();
const users = [
  {
    username: "admin",
    name: "Gustavo Alfredo Marín Sáez",
    password:
      "1b6ce880ac388eb7fcb6bcaf95e20083:341dfbbe86013c940c8e898b437aa82fe575876f2946a2ad744a0c51501c7dfe6d7e5a31c58d2adc7a7dc4b87927594275ca235276accc9f628697a4c00b4e01", // certamen123
  },
];

// Initialize reminders array
const reminders = [];

app.use(express.json());
app.use(express.static("public"));
// Escriba su código a partir de aquí

// Este es un middleware Se ejecuta antes de las rutas protegidas
const authMiddleware = (req, res, next) => {
  const token = req.header("X-Authorization");

  if (!token) {
    return res.status(401).json({ error: "No se proporciona ningún token" });
  }

  const user = users.find((u) => u.token === token);
  if (!user) {
    return res.status(401).json({ error: "Invalid token" });
  }

  req.user = user;
  next();
};

// Función auxiliar para verificar la contraseña usando scrypt
const verifyPassword = (password, storedPassword) => {
  const [salt, key] = storedPassword.split(":");
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey.toString("hex") === key);
    });
  });
};

// // Función que genera un hash seguro de una contraseña
const generatePasswordHash = (password) => {
  const salt = crypto.randomBytes(16).toString("hex");
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve(`${salt}:${derivedKey.toString("hex")}`);
    });
  });
};

// Login route
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ error: "Credenciales Invalidas" });
  }

  try {
    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: "Credenciales Invalidas" });
    }

    // Generate new token
    const token = crypto.randomBytes(48).toString("hex");
    user.token = token;

    res.json({
      username: user.username,
      name: user.name,
      token,
    });
  } catch (error) {
    res.status(500).json({ error: "Error Interno del Servidor" });
  }
});

// Ruta para obtener recordatorios
app.get("/api/reminders", authMiddleware, (req, res) => {
  // Crea una copia del array y la ordena
  const sortedReminders = [...reminders].sort((a, b) => {
    // Primero ordena por importancia
    if (a.important !== b.important) {
      // Si b es importante, va primero (retorna 1)
      // Si a es importante, va primero (retorna -1)
      return b.important ? 1 : -1;
    }
    // Si tienen la misma importancia, ordena por fecha
    // Los más recientes primero
    return a.createdAt - b.createdAt;
  });

  // Envía la lista ordenada como respuesta
  res.status(200).json(sortedReminders);
});

// Función auxiliar para validar el contenido
const validateContent = (content) => {
  // Verifica que sea un texto (string)
  if (typeof content !== "string") {
    return "El contenido debe ser una cadena(string)";
  }
  // Verifica que no esté vacío o solo tenga espacios
  if (!content.trim()) {
    return "El contenido no puede estar vacío.";
  }
  // Verifica que no exceda 120 caracteres
  if (content.length > 120) {
    return "El contenido no puede exceder los 120 caracteres";
  }
  // Si pasa todas las validaciones, retorna null
  return null;
};

// Ruta para crear un nuevo recordatorio
app.post("/api/reminders", authMiddleware, (req, res) => {
  // Extrae content e important del cuerpo de la petición
  const { content, important = false } = req.body;

  // Valida el contenido usando la función auxiliar
  const contentError = validateContent(content);
  if (contentError) {
    // Si hay error, devuelve código 400 y el mensaje
    return res.status(400).json({ error: contentError });
  }

  // Valida que important sea booleano
  if (important !== undefined && typeof important !== "boolean") {
    return res
      .status(400)
      .json({ error: "Importante debe ser un valor booleano" });
  }

  // Crea el nuevo recordatorio
  const newReminder = {
    id: crypto.randomUUID(), // Genera ID único
    content: content.trim(), // Elimina espacios extras
    createdAt: Date.now(), // Marca de tiempo actual
    important: important || false, // Usa el valor dado o false por defecto
  };

  // Agrega el recordatorio a la lista
  reminders.push(newReminder);
  // Devuelve el nuevo recordatorio con código 201 (Creado)
  res.status(201).json(newReminder);
});

// Ruta para actualizar un recordatorio existente
app.patch("/api/reminders/:id", authMiddleware, (req, res) => {
  // Obtiene el ID de los parámetros de la URL
  const { id } = req.params;
  // Obtiene content e important del cuerpo de la petición
  const { content, important } = req.body;

  // Busca el recordatorio por ID
  const reminder = reminders.find((r) => r.id === id);
  if (!reminder) {
    // Si no existe, devuelve error 404
    return res.status(404).json({ error: "Recordatorio no Encontrado" });
  }

  // Si se envió content, lo valida y actualiza
  if (content !== undefined) {
    const contentError = validateContent(content);
    if (contentError) {
      return res.status(400).json({ error: contentError });
    }
    reminder.content = content.trim();
  }

  // Si se envió important, lo valida y actualiza
  if (important !== undefined) {
    if (typeof important !== "boolean") {
      return res
        .status(400)
        .json({ error: "Important must be a boolean value" });
    }
    reminder.important = important;
  }

  // Devuelve el recordatorio actualizado
  res.status(200).json(reminder);
});

// Ruta para eliminar un recordatorio
app.delete("/api/reminders/:id", authMiddleware, (req, res) => {
  // Obtiene el ID de los parámetros de la URL
  const { id } = req.params;

  // Busca la posición del recordatorio en el array
  const reminderIndex = reminders.findIndex((r) => r.id === id);
  if (reminderIndex === -1) {
    // Si no encuentra el recordatorio, devuelve error 404
    return res.status(404).json({ error: "Recordatorio no encontrado" });
  }

  // Elimina el recordatorio del array
  reminders.splice(reminderIndex, 1);
  // Devuelve respuesta exitosa sin contenido (código 204)
  res.status(204).send();
});

// Ruta protegida (para pruebas)
app.get("/api/protected", authMiddleware, (req, res) => {
  // Devuelve un mensaje y el nombre del usuario autenticado
  res.json({
    message: "Esta es una ruta protegida",
    user: req.user.username,
  });
});

// Inicializar usuarios y arrancar el servidor
const initializeUsers = async () => {
  // Genera el hash de la contraseña 'admin123'
  const passwordHash = await generatePasswordHash("admin123");
  // Actualiza la contraseña del primer usuario (admin) con el hash generado
  users[0].password = passwordHash;
};

// Hasta aquí

app.listen(PORT, (error) => {
  if (error) {
    console.error(`No se puede ocupar el puerto ${PORT} :(`);
    return;
  }

  console.log(`Escuchando en el puerto ${PORT}`);
});
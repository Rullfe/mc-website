export default {
  async fetch(request, env, ctx) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    if (url.pathname === "/api/register") {
      return await handleRegister(request, env, corsHeaders);
    }
    if (url.pathname === "/api/login") {
      return await handleLogin(request, env, corsHeaders);
    }

    return new Response("404 Not Found", { status: 404, headers: corsHeaders });
  },
};

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltStr = btoa(String.fromCharCode(...salt));
  const passBuf = encoder.encode(password + saltStr);
  const hashBuf = await crypto.subtle.digest("SHA-256", passBuf);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  return saltStr + "$" + hashArr.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(rawPass, storedHash) {
  const [saltStr, oldHash] = storedHash.split("$");
  const encoder = new TextEncoder();
  const passBuf = encoder.encode(rawPass + saltStr);
  const hashBuf = await crypto.subtle.digest("SHA-256", passBuf);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  const newHash = hashArr.map(b => b.toString(16).padStart(2, "0")).join("");
  return newHash === oldHash;
}

async function handleRegister(req, env, headers) {
  const body = await req.json();
  const { username, password } = body;
  if (!username || !password) {
    return Response.json({ code: 400, msg: "账号密码不能为空" }, { headers });
  }
  const exist = await env.USER_DB.get(username);
  if (exist) {
    return Response.json({ code: 400, msg: "账号已存在" }, { headers });
  }
  const passHash = await hashPassword(password);
  await env.USER_DB.put(username, passHash);
  return Response.json({ code: 200, msg: "注册完成" }, { headers });
}

async function handleLogin(req, env, headers) {
  const body = await req.json();
  const { username, password } = body;
  const storedHash = await env.USER_DB.get(username);
  if (!storedHash) {
    return Response.json({ code: 400, msg: "账号不存在" }, { headers });
  }
  const ok = await verifyPassword(password, storedHash);
  if (!ok) {
    return Response.json({ code: 400, msg: "密码错误" }, { headers });
  }
  const tokenRaw = username + Date.now();
  const token = btoa(tokenRaw);
  return Response.json({ code: 200, token, msg: "登录成功" }, { headers });
}

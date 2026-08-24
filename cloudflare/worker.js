export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") return Response.json({status:"ok",edge:true});
    if (url.pathname.startsWith("/api/")) {
      if (!env.API_ORIGIN) return Response.json({error:"API_ORIGIN is not configured"},{status:500});
      const target = new URL(url.pathname + url.search, env.API_ORIGIN);
      const headers = new Headers(request.headers);
      headers.set("X-CyberGuard-Edge","cloudflare-worker");
      return fetch(new Request(target,{method:request.method,headers,
        body:["GET","HEAD"].includes(request.method)?undefined:request.body}));
    }
    return new Response("CyberGuard API Gateway",{status:200});
  }
};

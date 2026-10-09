package control

// 官方客户端的浏览器授权仍使用服务端 HTML 登录，因此保留最小登录脚本。
// 凭据管理和创建脚本已迁到 xunara-web；这里不再内嵌第二套管理页面。
const passkeyBrowserJS = `
function b64urlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
function bytesToB64url(bytes) {
  if (!bytes) return null;
  let binary = "";
  for (const value of new Uint8Array(bytes)) binary += String.fromCharCode(value);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function passkeyPost(url, body) {
  const resp = await fetch(url, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {})
  });
  let data = {};
  try { data = await resp.json(); } catch { data = {}; }
  if (!resp.ok) throw new Error(data.error || "Passkey sign-in failed; try again.");
  return data;
}
function decodeRequestOptions(options) {
  options.challenge = b64urlToBytes(options.challenge);
  for (const credential of options.allowCredentials || []) credential.id = b64urlToBytes(credential.id);
  return options;
}
function encodeAssertion(credential) {
  return {
    id: credential.id, rawId: bytesToB64url(credential.rawId), type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
      authenticatorData: bytesToB64url(credential.response.authenticatorData),
      signature: bytesToB64url(credential.response.signature),
      userHandle: bytesToB64url(credential.response.userHandle)
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}
`

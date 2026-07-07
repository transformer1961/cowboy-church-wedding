exports.handler = async () => ({
  statusCode: 410,
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    error: "Logout is handled by the static admin page in this version."
  })
});

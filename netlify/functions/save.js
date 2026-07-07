exports.handler = async () => ({
  statusCode: 410,
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    error: "Content saving is handled in browser storage in this version."
  })
});

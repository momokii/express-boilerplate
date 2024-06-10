module.exports =  function throwErr(msg, code) {
    const err = new Error(msg)
    err.statusCode = code
    throw err
}
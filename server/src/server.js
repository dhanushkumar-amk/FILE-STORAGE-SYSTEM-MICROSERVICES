const logger = require('./utils/logger.js')

const express = require('express')
const app = express()

app.get('/', (req, res) => {
  res.send('hello world')
})

app.listen(3000, () => {
  logger.info('server is running on port 3000')
})

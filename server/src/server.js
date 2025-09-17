const logger = require('./utils/logger.js')
const errorHandler = require('./middlewares/errorHandler.js')

const cors = require('cors')

const express = require('express')
const app = express()


// middleware
app.use(errorHandler)
app.use(cors())
app.use(express.json())


app.get('/', (req, res) => {
  res.send('hello world')
})

app.listen(3000, () => {
  logger.info('server is running on port 3000')
})

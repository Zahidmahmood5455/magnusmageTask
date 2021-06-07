const mongoose = require('mongoose');
// const dotenv = require('dotenv');

// dotenv.config({ path: './config.env' });
const app = require('./app');

const DB = 'mongodb://127.0.0.1:27017/magnustask'
// process.env.DATABASE.replace(
// //   '<password>',
// //   process.env.DATABASE_PASSWORD
// // );
mongoose.connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('connection successful');
  })
  .catch((err) => {
    console.log('Error :', err.name);
  });
const port = 8000;
const server = app.listen(port, () => {
  console.log('server start');
});
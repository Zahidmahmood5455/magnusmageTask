const express = require('express');
const userRouter = require('./routes/userRoutes');

const app = express();

app.use(express.json());

app.use('/users', userRouter);

app.use((err, req, res, next) => {
    return res.status(404).json({
        status: 'fail',
        message: err.message,
      });
});

module.exports = app;
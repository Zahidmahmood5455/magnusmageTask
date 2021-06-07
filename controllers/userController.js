const User = require('../model/userModel');

const filterObj = (obj, ...allowdFields) => {
    const newObj = {};
    Object.keys(obj).forEach((el) => {
      if (allowdFields.includes(el)) {
        newObj[el] = obj[el];
      }
    });
    return newObj;
  };

exports.updateUser = async (req, res, next) => {
    if (req.body.password || req.body.passwordConfirm)
    return next(new Error('this route is not for password update.'));
    const filteredBody = filterObj(req.body, 'name', 'email');
    try {
        const doc = await User.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true,
        });

        res.status(200).json({
        status: 'success',
        data: {
            data: doc,
        },
        });
    } catch (err) {
        res.status(201).json({
            status: 'fail',
            message: err.message
        });
    }

};
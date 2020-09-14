function protected(req, res, next) {
    if (req.session.username) {
        next();
    } else {
        res.status(401).json({ message: "you cannot pass!" });
    }
}

module.exports = protected
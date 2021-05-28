const passport = require('passport')
const localStrategy = require('passport-local').Strategy
const userModel = require('../models/UserModel')

passport.use(
	new localStrategy(
		{ usernameField: 'email' },
		async (username, password, done) => {
			try {
				const user = await userModel.findOne({ email: username }).exec()
				if (!user) return done(null, false, { message: 'invalid username' })
				const passwordOk = user.comparePassword(password)
				if (!passwordOk) {
					return done(null, false, { message: 'invalid username' })
				}
				return done(null, user)
			} catch (error) {
				done(error)
			}
		}
	)
)

passport.serializeUser((user, done) => {
	return done(null, user._id)
})

passport.deserializeUser(async (id, done) => {
	try {
		const user = userModel.findById(id).exec()
		return done(null, user)
	} catch (error) {
		return done(error)
	}
})

module.exports = {
	initialized: passport.initialize(),
	session: passport.session(),
	setUser: (req, res, next) => {
		res.locals.user = req.user
		return next()
	},
}

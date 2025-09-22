const { getUser } = require("../service/auth");

function restrictToLoggedinUserOnly(req, res, next){
    try {
        const accepts = (req.get && req.get('accept')) || '';
        const isApiRequest = (req.originalUrl && req.originalUrl.startsWith('/api')) || (req.path && req.path.startsWith('/api')) || (accepts && accepts.includes('application/json')) || req.xhr;
        const userUid = req.cookies?.uid;

        if(!userUid) {
            console.log('No user cookie found, redirecting to login');
            if(isApiRequest){
                return res.status(401).json({ error: 'Unauthorized' });
            }
            return res.redirect("/login");
        }

        const user = getUser(userUid);

        if(!user) {
            console.log('Invalid or expired token, redirecting to login');
            if(isApiRequest){
                return res.status(401).json({ error: 'Unauthorized' });
            }
            return res.redirect("/login");
        }
        // console.log('this is the user ?',user);

        req.user = user;
        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        const accepts = (req.get && req.get('accept')) || '';
        const isApiRequest = (req.originalUrl && req.originalUrl.startsWith('/api')) || (req.path && req.path.startsWith('/api')) || (accepts && accepts.includes('application/json')) || req.xhr;
        if(isApiRequest){
            return res.status(500).json({ error: 'Auth middleware error' });
        }
        return res.redirect("/login");
    }
}


module.exports = { restrictToLoggedinUserOnly }
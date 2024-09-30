import express from 'express';

const router = express.Router();

router.get('/test', (req, res) => {
  res.json({
    message: 'User route works!',
  });
});

export default router;

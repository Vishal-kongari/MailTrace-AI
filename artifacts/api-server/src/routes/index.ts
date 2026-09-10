import { Router, type IRouter } from "express";
import healthRouter from "./health";
import mailtraceRouter from "./mailtrace";

const router: IRouter = Router();

router.use(healthRouter);
router.use(mailtraceRouter);

export default router;

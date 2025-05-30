import express, { NextFunction, Request, Response } from "express";
import routes from "./routes";
import cors from "cors";

const app = express();

app.use(
    cors({
        origin: "*",
        credentials: true,
    }),
);

app.use(express.json());

app.use("/", routes);

app.use((req: Request, res: Response) => {
    res.status(404).json({ error: "Not Found" });
});

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error(err.stack);
    res.status(500).json({ error: "Internal Server Error" });
});

const PORT = parseInt(process.env.PORT ?? "8080");
const HOST = process.env.HOST ?? "0.0.0.0";

app.listen(PORT, HOST, () => {
    console.log(`Server running at http://${HOST}:${PORT}`);
});

const { MongoClient } = require("mongodb");
const express = require("express");
const helmet = require("helmet");
const morgan = require("morgan");

const dbclient = new MongoClient();
const collection = dbclient.db("test").collection("main");

app = express();
app.use(express.json());
app.use(helmet.hidePoweredBy());
app.use(morgan("tiny"));

const server = app.listen(3000, (error) => console.log(!error ? "Server listen on 3000 port." : "Exception: " + error));

app.route("/api/db")
    .get(async (req, res) => {
        try {
            const db_response = await collection.find().toArray();
            res.json({"response": db_response});
        } catch(e) {
            res.status(500).json({"response": `Failure executing this operation: ${e}.`});
        }
    })
    .post(async (req, res) => {
        try {
            const { type, json } = req.body;
            if (!type || !json)
                return res.json({"response": "Check your json."})
            const db_response = type === "all" ? await collection.insertMany(json) : await collection.insertOne(json);
            res.json({"response": db_response});
        } catch(e) {
            res.status(500).json({"response": `Failure executing this operation: ${e}.`});
        }
    })
    .delete(async (req, res) => {
        try {
            const { type, query } = req.body;
            if (!type || !query)
                return res.json({"response": "Check your json."})
            const db_response = type === "all" ? await collection.delete(query) : await collection.deleteOne(query);
            res.json({"response": db_response});
        } catch(e) {
            res.status(500).json({"response": `Failure executing this operation: ${e}.`});
        }
    })

app.get("/close", async (req, res) => {
    try {
        await dbclient.close();
        res.json({"response": "Successful."});
    } catch(e) {
        res.status(500).json({"response": `Failure closing mongo client: ${e}.`});
    } finally {
        server.close();
    }
});

app.use((req, res, next) => res.sendStatus(404));
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.sendStatus(404);
});

const express = require('express');
const PORT = 5000
const app = express();

app.get('/', (req, res) => res.json({message: 'time 2 code'}));

app.listen(PORT, () => console.log("Started server on port", PORT));
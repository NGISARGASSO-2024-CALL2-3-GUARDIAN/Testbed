const http = require('http');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    let fileName = req.headers['x-file-name'];
    let filePath = path.join(__dirname, 'uploads', fileName);
    let fileStream = fs.createWriteStream(filePath);
    req.pipe(fileStream);

    req.on('end', () => {
      console.log(`File ${fileName} received and saved at ${filePath}`);
      res.writeHead(200);
      res.end('File received and saved successfully\n');
    });
  } else if (req.method === 'GET') {
    fs.readdir(path.join(__dirname, 'uploads'), (err, files) => {
      if (err) {
        res.writeHead(500);
        res.end('Internal server error\n');
      } else {
        let imageFile = files.find(file => file.endsWith('.jpg') || file.endsWith('.jpeg') || file.endsWith('.png'));
        if (imageFile) {
          let imagePath = path.join(__dirname, 'uploads', imageFile);
          let imageStream = fs.createReadStream(imagePath);
          imageStream.pipe(res);
        } else {
          res.writeHead(404);
          res.end('Image not found\n');
        }
      }
    });
  } else {
    res.writeHead(404);
    res.end('Endpoint not found\n');
  }
});

const PORT = 80;

server.listen(PORT, () => {
  console.log(`HTTP server running on port ${PORT}`);
});
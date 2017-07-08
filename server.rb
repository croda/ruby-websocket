require 'socket'
require 'digest/sha1'

server = TCPServer.new('localhost',4202)

loop do

  #wait for a connection
  socket = server.accept
  STDERR.puts "Incoming Request"

  #Read the HTTP requrest, We know it's finished when we see a line with nothing but \r\n
  http_request = ""
  while (line = socket.gets) && (line != "\r\n")
    http_request += line
  end

  #Grab security key from headers
  #if one isn't present, close connection
  if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/)
    websocket_key = matches[1]
    STDERR.puts "Websocket handshake detected with key: #{ websocket_key }"
  else
    STDERR.puts "Closing non-websocket connection"
    socket.close
    next
  end

  #Take the value provided by the client, append a magic
  #string to it. Generate the SHA1 hash, then base64 encode it
  #response_key = Digest::SHA1.base64digest([sec_websocket_accept, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].join)
  response_key = Digest::SHA1.base64digest([websocket_key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].join)
  STDERR.puts "Responding to handshake with key: #{ response_key }"

  socket.write <<-eos
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: #{ response_key }

  eos


  STDERR.puts "Handshake completed. Starting to parse websocket frame"

  first_byte = socket.getbyte
  fin = first_byte & 0b10000000
  opcode = first_byte & 0b00001111

  #only supporting single-frame text messages
  raise "We don't support continuations" unless fin
  raise "We only support opcode 1" unless opcode == 1

  second_byte = socket.getbyte
  is_masked = second_byte & 0b10000000
  payload_size = second_byte & 0b01111111

  raise "All frames sent to a server shoul be masked" unless is_masked
  raise "We only support payloads < 126 bytes in length" unless payload_size < 126

  STDERR.puts "Payload size: #{ payload_size } bytes"

  mask = 4.times.map { socket.getbyte }
  STDERR.puts "Got mask: #{ mask.inspect }"

  data = payload_size.times.map { socket.getbyte }
  STDERR.puts "Got masked data: #{ data.inspect }"

  unmasked_data = data.each_with_index.map { |byte, i| byte ^ mask[i % 4]}
  STDERR.puts "Converted to a string: #{ unmasked_data.pack('C*').force_encoding('utf-8').inspect }"

  response = "Loud and clear!"
  STDERR.puts "Sending response: #{ response.inspect }"

  output = [0b10000001, response.size, response]
  socket.write output.pack("CCA#{ response.size }")
end

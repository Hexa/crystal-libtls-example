require "libtls"
require "option_parser"
require "socket"

address = "127.0.0.1"
port = 443

OptionParser.parse do |parser|
  parser.banner = "Usage: ./server [arguments]"
  parser.on("-a ADDRESS", "--address ADDRESS", "") { |name| address = name }
  parser.on("-p PORT", "--port PORT", "") { |name| port = name.to_i }
  parser.on("-h", "--help", "Show this help") do
    puts parser
    exit 1
  end
  parser.missing_option { exit 1 }
  parser.invalid_option { exit 255 }
end

cert_file = "./cert/server.pem"
key_file = "./cert/server.key"

LibTls.tls_init
cctx = LibTls.tls_server
cctx_ptr = pointerof(cctx)
config = LibTls.tls_config_new
unless config
  exit 1
end
ret = LibTls.tls_config_set_cert_file(config, cert_file)
unless ret == 0
  puts String.new(LibTls.tls_config_error(config))
  exit 1
end
ret = LibTls.tls_config_set_key_file(config, key_file)
unless ret == 0
  puts String.new(LibTls.tls_config_error(config))
  exit 1
end
ctx = LibTls.tls_server
unless ctx
  exit 1
end
ret = LibTls.tls_configure(ctx, config)
unless ret == 0
  puts String.new(LibTls.tls_error(ctx))
  exit 1
end

server = TCPServer.new(address, port)

while socket = server.accept?
  ret = LibTls.tls_accept_socket(ctx, cctx_ptr, socket.fd)
  unless ret == 0
    puts String.new(LibTls.tls_error(ctx))
    exit 1
  end
  buf = Bytes.new(0xffff)
  message = ""
  loop do
    len = LibTls.tls_read(cctx, buf, buf.size)
    if len < -1
      next
    elsif len == -1
      puts String.new(LibTls.tls_error(cctx))
      break
    else
      puts message = String.new(buf)
      break
    end
  end

  loop do
    len = LibTls.tls_write(cctx, message, message.size)
    if len < -1
      next
    elsif len == -1
      puts String.new(LibTls.tls_error(cctx))
      break
    else
      break
    end
  end
end

LibTls.tls_close(ctx)
LibTls.tls_close(cctx)
LibTls.tls_config_free(config)
LibTls.tls_free(ctx)
LibTls.tls_free(cctx)

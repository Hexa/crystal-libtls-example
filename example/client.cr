require "libtls"
require "option_parser"

address = "127.0.0.1"
port = "443"
message = ""

OptionParser.parse do |parser|
  parser.banner = "Usage: ./client [arguments]"
  parser.on("-a ADDRESS", "--address ADDRESS", "") { |name| address = name }
  parser.on("-p PORT", "--port PORT", "") { |name| port = name }
  parser.on("-m MESSAGE", "--message MESSAGE", "") { |name| message = name }
  parser.on("-h", "--help", "Show this help") do
    puts parser
    exit 1
  end
  parser.missing_option { exit 1 }
  parser.invalid_option { exit 255 }
end

exit 1 if message.empty?

LibTls.tls_init
ctx = LibTls.tls_client
config = LibTls.tls_config_new
LibTls.tls_config_set_protocols(config, LibTls::TLS_PROTOCOL_TLSv1_2)
LibTls.tls_config_insecure_noverifycert(config)
LibTls.tls_config_insecure_noverifyname(config)
LibTls.tls_config_insecure_noverifytime(config)
ret = LibTls.tls_configure(ctx, config)
unless ret == 0
  puts String.new(LibTls.tls_error(ctx))
  exit 1
end
ret = LibTls.tls_connect(ctx, address, port)
unless ret == 0
  puts String.new(LibTls.tls_error(ctx))
  exit 1
end
ret = LibTls.tls_handshake(ctx)
unless ret == 0
  puts String.new(LibTls.tls_error(ctx))
  exit 1
end

loop do
  len = LibTls.tls_write(ctx, message, message.size)
  if len < -1
    next
  elsif len == -1
    puts String.new(LibTls.tls_error(ctx))
    exit 1
  else
    break
  end
end

buf = Bytes.new(0xffff)
loop do
  len = LibTls.tls_read(ctx, buf, buf.size)
  if len < -1
    next
  elsif len == -1
    puts String.new(LibTls.tls_error(ctx))
    exit 1
  else
    puts message = String.new(buf)
    break
  end
end

LibTls.tls_close(ctx)
LibTls.tls_config_free(config)
LibTls.tls_free(ctx)

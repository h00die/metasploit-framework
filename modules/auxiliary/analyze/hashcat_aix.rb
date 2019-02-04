##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/hashcat'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Hashcat

  def initialize
    super(
      'Name'            => 'Hashcat AIX Password Cracker',
      'Description'     => %Q{
          This module uses Hashcat to identify weak passwords that have been
        acquired from passwd files on AIX systems.  These utilize DES hashing.
        descript is format 1500 in Hashcat.
      },
      'Author'          => ['h00die'],
      'License'         => MSF_LICENSE
    )
  end

  def run
    cracker = new_hashcat_cracker

    # hashes is an array to re-reference after cracking
    # format: ['hash:username:id']
    # create the hash file first, so if there aren't any hashes we can quit early
    cracker.hash_path, hashes = hash_file

    # generate our wordlist and close the file handle.  max length of DES is 8
    wordlist = wordlist_file(8)
    unless wordlist
      print_error('This module cannot run without a database connected. Use db_connect to connect to a database.')
      return
    end

    wordlist.close
    print_status "Wordlist file written out to #{wordlist.path}"
    cracker.wordlist = wordlist.path

    cleanup_files = [cracker.hash_path, wordlist.path]

    ['descrypt'].each do |format|
      # dupe our original cracker so we can safely change options between each run
      cracker_instance = cracker.dup
      cracker_instance.format = jtr_format_to_hashcat_format(format)
      print_status "Cracking #{format} hashes in normal wordlist mode..."
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracking #{format} hashes in increment mode..."
      cracker_instance.wordlist = nil
      cracker_instance.attack = '3'
      cracker_instance.increment = true
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracked Passwords this run:"
      cracker_instance.each_cracked_password do |password_line|
        password_line.chomp!
        next if password_line.blank?
        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        next unless fields.count ==2
        hash = fields.shift
        password = fields.join(':') # Anything left must be the password. This accounts for passwords with : in them
        hashes.each do |h|
          h = h.split(":")
          next unless h[0] == hash
          username = h[1]
          core_id  = h[2]
          print_good "#{username}:#{password}"
          create_cracked_credential( username: username, password: password, core_id: core_id)
        end
      end
    end
    cleanup_files.each do |f|
      File.delete(f)
    end
  end

  def hash_file
    hashes = []
    wrote_hash = false
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NonreplayableHash').each do |core|
      if core.private.jtr_format =~ /des/
        hashes << "#{core.private.data}:#{core.public.username}:#{core.id}"
        hashlist.puts hash_to_hashcat(core)
        wrote_hash = true
      end
    end
    hashlist.close
    unless wrote_hash # check if we wrote anything and bail early if we didn't
      hashlist.delete
      fail_with Failure::NotFound, 'No DES hashes in database to crack'
    end
    print_status "Hashes Written out to #{hashlist.path}"
    return hashlist.path, hashes
  end
end

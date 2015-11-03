class SignController < ActionController::Base
  def index
    cert = OpenSSL::X509::Certificate.new(File.read("#{Rails.public_path.to_s}/mycertificates.cer"))
    test = sign(build_xml, cert)
    binding.pry
  end

  def build_xml
    builder = Nokogiri::XML::Builder.new(encoding: "ISO-8859-1") do |xml|
         xml.Message do
           xml.MessageId do
             xml.ServiceId "SolicitaLogon"
             xml.Version 1.0
             xml.MsgDesc "Solicitação do Desafio de Logon"
             xml.Code Time.now.strftime("%H%M%S")
             xml.FromAddress "PGM"
             xml.ToAddress "TJCE"
             xml.Date (I18n.l  Date.today, format: :xml)
           end
           xml.MessageBody
         end
       end

       builder.to_xml
  end

  def sign(xml, certificate)
    xml = Nokogiri::XML(xml.to_s, &:noblanks)
    private_key = OpenSSL::PKey::RSA.new(File.read("#{Rails.public_path.to_s}/privateKey.pem"), '12345678')

    xml_canon  = xml.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
    xml_digest = Base64.encode64(OpenSSL::Digest::SHA1.digest(xml_canon)).strip

    signature = xml.xpath("//ds:Signature", "ds" => "http://www.w3.org/2000/09/xmldsig#").first
    unless signature
      signature = Nokogiri::XML::Node.new('Signature', xml)
      signature.default_namespace = 'http://www.w3.org/2000/09/xmldsig#'
      xml.root().add_child(signature)
    end

    signature_info = Nokogiri::XML::Node.new('SignedInfo', xml)

    child_node = Nokogiri::XML::Node.new('CanonicalizationMethod', xml)
    child_node['Algorithm'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'
    signature_info.add_child child_node

    child_node = Nokogiri::XML::Node.new('SignatureMethod', xml)
    child_node['Algorithm'] = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    signature_info.add_child child_node

    reference = Nokogiri::XML::Node.new('Reference', xml)
    reference['URI'] = ''

    transforms = Nokogiri::XML::Node.new('Transforms', xml)

    child_node  = Nokogiri::XML::Node.new('Transform', xml)
    child_node['Algorithm'] = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
    transforms.add_child child_node

    child_node  = Nokogiri::XML::Node.new('Transform', xml)
    child_node['Algorithm'] = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
    transforms.add_child child_node

    child_node  = Nokogiri::XML::Node.new('DigestMethod', xml)
    child_node['Algorithm'] = 'http://www.w3.org/2000/09/xmldsig#sha1'
    reference.add_child child_node

    child_node         = Nokogiri::XML::Node.new('DigestValue', xml)
    child_node.content = xml_digest
    reference.add_child child_node

    signature_info.add_child reference
    signature.add_child signature_info

    sign_canon      = signature_info.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
    signature_hash  = private_key.sign(OpenSSL::Digest::SHA1.new, sign_canon)
    signature_value = Base64.encode64( signature_hash ).gsub("\n", '')

    child_node = Nokogiri::XML::Node.new('SignatureValue', xml)
    child_node.content = signature_value
    signature.add_child child_node

    key_info = Nokogiri::XML::Node.new('KeyInfo', xml)

    x509_data = Nokogiri::XML::Node.new('X509Data', xml)
    x509_certificate = Nokogiri::XML::Node.new('X509Certificate', xml)
    x509_certificate.content = certificate.to_s.gsub(/\-\-\-\-\-[A-Z]+ CERTIFICATE\-\-\-\-\-/, "").gsub(/\n/,"")

    x509_data.add_child x509_certificate
    key_info.add_child x509_data

    signature.add_child key_info

    xml.root().add_child signature

    xml.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
  end
end

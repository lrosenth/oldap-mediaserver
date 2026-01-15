require 'java'
require "net/http"
require 'cgi'
require "json"
require "uri"
require "openssl"
require "base64"

LOGGER = Java::edu.illinois.library.cantaloupe.delegate.Logger

##
# Sample Ruby delegate script containing stubs and documentation for all
# available delegate methods. See the user manual for more information.
#
# The application will create an instance of this class early in the request
# cycle and dispose of it at the end of the request cycle. Instances don't need
# to be thread-safe, but sharing information across instances (requests)
# **does** need to be done thread-safely.
#
# This version of the script works with Cantaloupe version >= 5.
#
class CustomDelegate
    # ---------------------------
    # Configuration via environment
    # ---------------------------
    JWT_SECRET = ENV.fetch("OLDAP_JWT_SECRET") # MUST be set
    IMAGE_ROOT = ENV.fetch("OLDAP_IMAGE_ROOT", "/data/images")
    JWT_ISS    = ENV.fetch("OLDAP_JWT_ISS", "http://oldap.org")
    OLDAP_API_BASE = ENV.fetch("OLDAP_API_BASE", "http://oldap-api")
    OLDAP_UNKNOWN_PASSWORD = ENV.fetch("OLDAP_UNKNOWN_PASSWORD", "")
    OLDAP_UNKNOWN_USERID = ENV.fetch("OLDAP_UNKNOWN_USERID", "unknown")

  ##
  # Attribute for the request context, which is a hash containing information
  # about the current request.
  #
  # This attribute will be set by the server before any other methods are
  # called. Methods can access its keys like:
  #
  # ```
  # identifier = context['identifier']
  # ```
  #
  # The hash will contain the following keys in response to all requests:
  #
  # * `client_ip`        [String] Client IP address.
  # * `cookies`          [Hash<String,String>] Hash of cookie name-value pairs.
  # * `full_size`        [Hash<String,Integer>] Hash with `width` and `height`
  #                      keys corresponding to the pixel dimensions of the
  #                      source image.
  # * `identifier`       [String] Image identifier.
  # * `local_uri`        [String] URI seen by the application, which may be
  #                      different from `request_uri` when operating behind a
  #                      reverse-proxy server.
  # * `metadata`         [Hash<String,Object>] Embedded image metadata. Object
  #                      structure varies depending on the source image.
  #                      See the `metadata()` method.
  # * `page_count`       [Integer] Page count.
  # * `page_number`      [Integer] Page number.
  # * `request_headers`  [Hash<String,String>] Hash of header name-value pairs.
  # * `request_uri`      [String] URI requested by the client.
  # * `scale_constraint` [Array<Integer>] Two-element array with scale
  #                      constraint numerator at position 0 and denominator at
  #                      position 1.
  #
  # It will contain the following additional string keys in response to image
  # requests, after the image has been accessed:
  #
  # * `operations`     [Array<Hash<String,Object>>] Array of operations in
  #                    order of application. Only operations that are not
  #                    no-ops will be included. Every hash contains a `class`
  #                    key corresponding to the operation class name, which
  #                    will be one of the `e.i.l.c.operation.Operation`
  #                    implementations.
  # * `output_format`  [String] Output format media (MIME) type.
  # * `resulting_size` [Hash<String,Integer>] Hash with `width` and `height`
  #                    keys corresponding to the pixel dimensions of the
  #                    resulting image after all operations have been applied.
  #
  # @return [Hash] Request context.
  #
  attr_accessor :context

  ##
  # Deserializes the given meta-identifier string into a hash of its component
  # parts.
  #
  # This method is used only when the `meta_identifier.transformer`
  # configuration key is set to `DelegateMetaIdentifierTransformer`.
  #
  # The hash contains the following keys:
  #
  # * `identifier`       [String] Required.
  # * `page_number`      [Integer] Optional.
  # * `scale_constraint` [Array<Integer>] Two-element array with scale
  #                      constraint numerator at position 0 and denominator at
  #                      position 1. Optional.
  #
  # @param meta_identifier [String]
  # @return Hash<String,Object> See above. The return value should be
  #                             compatible with the argument to
  #                             {serialize_meta_identifier}.
  #
  def deserialize_meta_identifier(meta_identifier)
  end

  ##
  # Serializes the given meta-identifier hash.
  #
  # This method is used only when the `meta_identifier.transformer`
  # configuration key is set to `DelegateMetaIdentifierTransformer`.
  #
  # See {deserialize_meta_identifier} for a description of the hash structure.
  #
  # @param components [Hash<String,Object>]
  # @return [String] Serialized meta-identifier compatible with the argument to
  #                  {deserialize_meta_identifier}.
  #
  def serialize_meta_identifier(components)
  end

    ##
    # Analyze the JWT token that is passed as query parameter ?token=...
    #
    # @param token The token string
    # @ return [Hash<String,String>] key-value pairs of the content of the JWT payload
    #
    def jwt_payload_from_query_token(token)
        unless @payload
            @payload = jwt_decode_hs256(token, JWT_SECRET)

            # iss check
            iss = @payload["iss"].to_s
            if iss != JWT_ISS
                STDERR.puts "[delegate.jwt_payload_from_query_token] iss mismatch token_iss=#{iss.inspect} expected=#{JWT_ISS.inspect}"
                return nil
            end

            # exp check (Python expiration.timestamp() -> float)
            exp = @payload["exp"]
            exp_i = exp.is_a?(Numeric) ? exp.to_i : exp.to_s.to_i
            now_i = Time.now.to_i
            if exp_i <= now_i
                STDERR.puts "[delegate.jwt_payload_from_query_token] expired exp=#{exp_i} now=#{now_i}"
                return nil
            end
        end
        return @payload

        rescue => e
            STDERR.puts "[delegate.jwt_payload_from_query_token] exception #{e.class}: #{e.message}"
            nil
    end

    # ---- Minimal HS256 implementation ----
    ##
    # Used to decode the JWT token
    #
    # @param token [String] The JWT token string
    # @param secret [String] The secret necessary for decoding the token
    # @return [Hash<String, String>] The deocded information as key-value pairs
    #
    def jwt_decode_hs256(token, secret)
        header_b64, payload_b64, sig_b64 = token.split(".", 3)
        return nil unless header_b64 && payload_b64 && sig_b64

        signing_input = "#{header_b64}.#{payload_b64}"
        expected = OpenSSL::HMAC.digest("sha256", secret, signing_input)
        expected_b64 = b64url_encode(expected)

        unless secure_compare(expected_b64, sig_b64)
            STDERR.puts '[delegate ERROR:] JWT signature mismatch'
            return nil
        end

        payload_json = b64url_decode(payload_b64)
        JSON.parse(payload_json)
    end

    ##
    # Decode a base64 string
    #
    # @param str [String] String to decode.
    # @return [String] Decoded string
    #
    def b64url_decode(str)
        s = str.tr("-_", "+/")
        s += "=" * ((4 - s.length % 4) % 4)
        Base64.decode64(s)
    end

    ##
    # Encode a binary string to base64
    #
    # @param bin [String] String to be encoded
    # @return [String] Encoded string
    #
    def b64url_encode(bin)
        Base64.strict_encode64(bin).tr("+/", "-_").gsub("=", "")
    end

    def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize
        res = 0
        a.bytes.zip(b.bytes) { |x, y| res |= (x ^ y) }
        res == 0
    end

    # ---------------------------
    # Helpers
    # ---------------------------
    def unauthorized(msg)
        {
        "status_code" => 401,
        "challenge"   => 'Bearer charset="UTF-8"',
        "body"        => msg
        }
    end


    # ---------------------------
    # OLDAP helpers (incremental)
    # ---------------------------

    def oldap_http_for(uri)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.read_timeout = 10
        http.open_timeout = 5
        http
    end

    def oldap_login_unknown!
        uri = URI("#{OLDAP_API_BASE}/admin/auth/#{OLDAP_UNKNOWN_USERID}")
        req = Net::HTTP::Post.new(uri.request_uri)
        req["Content-Type"] = "application/json"
        req.body = { password: OLDAP_UNKNOWN_PASSWORD }.to_json

        STDERR.puts "[delegate.oldap_login_unknown] POST #{uri}"

        resp = oldap_http_for(uri).request(req)
        STDERR.puts "[delegate.oldap_login_unknown] status=#{resp.code}"

        return nil unless resp.is_a?(Net::HTTPSuccess)

        data = JSON.parse(resp.body) rescue {}
        user_token = data["token"]
        STDERR.puts "[delegate.oldap_login_unknown] got_token=#{!user_token.to_s.empty?}"
        user_token
    rescue => e
        STDERR.puts "[delegate.oldap_login_unknown] exception #{e.class}: #{e.message}"
        nil
    end

    # Simple TTL cache to avoid login on every request
    def unknown_user_token
        @@unknown_user_token ||= nil
        @@unknown_user_token_exp ||= 0

        now = Time.now.to_i
        return @@unknown_user_token if @@unknown_user_token && now < @@unknown_user_token_exp

        tok = oldap_login_unknown!
        if tok
            @@unknown_user_token = tok
            @@unknown_user_token_exp = now + 600 # 10 minutes
        end
        tok
    end

    def unknown_permitted_for_identifier?(identifier)
        tok = unknown_user_token
        return false unless tok

        # STEP 1: just prove we have a token:
        STDERR.puts "[delegate.unknown_perm] have_unknown_token=true id=#{identifier}"
        return true   # TEMPORARY: allow everything for now

        # STEP 2 (later): fetch MediaObject, compute permval, return permval>=1
    end

    def oldap_get_mediaobject_json(id, tok)
        # Path param must be escaped properly:
        id_esc = URI.encode_www_form_component(id.to_s)
        uri = URI("#{OLDAP_API_BASE}/data/mediaobject/id/#{id_esc}")

        req = Net::HTTP::Get.new(uri.request_uri)
        req["Authorization"] = "Bearer #{tok}"
        req["Accept"] = "application/json"

        STDERR.puts "[delegate.oldap_get_mediaobject] GET #{uri}"

        resp = oldap_http_for(uri).request(req)
        STDERR.puts "[delegate.oldap_get_mediaobject] status=#{resp.code}"

        return nil unless resp.is_a?(Net::HTTPSuccess)

        JSON.parse(resp.body)
    rescue => e
        STDERR.puts "[delegate.oldap_get_mediaobject] exception #{e.class}: #{e.message}"
        nil
    end

    def unknown_mediaobject_access(identifier)
        return @mediainfo if defined?(@mediainfo)
        tok = unknown_user_token
        unless tok
            @mediainfo = nil
            return nil
        end

        obj = oldap_get_mediaobject_json(identifier, tok)
        unless obj
            @mediainfo = nil
            return nil
        end

        permval = obj["permval"].to_i
        path    = obj["shared:path"].to_s

        STDERR.puts "[delegate.unknown_mediaobject_access] id=#{identifier} permval=#{permval} path=#{path.inspect}"

        @mediainfo = { "permval" => permval, "path" => path }
    end


    ##
    # Get the query parameter "token" (?token=...) from the context. It uses the "context['local_uri']"
    # because that's where the complete URL including the query parameters is given
    #
    # @return [String | nil] The token, or nil, if there is no token given
    #
    def get_token(options = {})
        unless @token
            uri_string = context['local_uri']
            if uri_string
                query_string = URI.parse(uri_string).query
                query_params = CGI.parse(query_string) if query_string

                # Now you can access specific parameters
                if query_params && query_params['token']
                    # query_params['my_param'] will be an array of values
                    @token = query_params['token'].first
                else
                    return nil
                end
            else
                return nil
            end
        end
        return @token
    end

  ##
  # Returns authorization status for the current request. This method is called
  # upon all requests to all public endpoints early in the request cycle,
  # before the image has been accessed. This means that some context keys (like
  # `full_size`) will not be available yet.
  #
  # This method should implement all possible authorization logic except that
  # which requires any of the context keys that aren't yet available. This will
  # ensure efficient authorization failures.
  #
  # Implementations should assume that the underlying resource is available,
  # and not try to check for it.
  #
  # Possible return values:
  #
  # 1. Boolean true/false, indicating whether the request is fully authorized
  #    or not. If false, the client will receive a 403 Forbidden response.
  # 2. Hash with a `status_code` key.
  #     a. If it corresponds to an integer from 200-299, the request is
  #        authorized.
  #     b. If it corresponds to an integer from 300-399:
  #         i. If the hash also contains a `location` key corresponding to a
  #            URI string, the request will be redirected to that URI using
  #            that code.
  #         ii. If the hash also contains `scale_numerator` and
  #            `scale_denominator` keys, the request will be
  #            redirected using that code to a virtual reduced-scale version of
  #            the source image.
  #     c. If it corresponds to 401, the hash must include a `challenge` key
  #        corresponding to a WWW-Authenticate header value.
  #
  # @param options [Hash] Empty hash.
  # @return [Boolean,Hash<String,Object>] See above.
  #
    def pre_authorize(options = {})
        uri_string = context['local_uri']
        STDERR.puts '[delegate.pre_authorize] Using URL #{uri_string} for authorization'

        permval = nil
        token = get_token()
        if token
            payload = jwt_payload_from_query_token(token)
            if payload
                permval = payload["permval"].to_i
            end
        end
        unless permval
            info = unknown_mediaobject_access(context["identifier"])
            unless info
                STDERR.puts "[delegate.pre_authorize] Unknown user: no media object found"
                return unauthorized("No access for unknown user")
            end
            permval = info["permval"]
        end

        STDERR.puts '[delegate.pre_authorize] pre_authorize: Permission permval=#{permval}'

        return true if permval >= 1

        STDERR.puts '[delegate.pre_authorize] pre_authorize: Permission denied permval=#{permval}'
        return unauthorized("Not permitted")
    end


  ##
  # Returns authorization status for the current request. Will be called upon
  # all requests to all public image (not information) endpoints.
  #
  # This is a counterpart of `pre_authorize()` that is invoked later in the
  # request cycle, once more information about the underlying image has become
  # available. It should only contain logic that depends on context keys that
  # contain information about the source image (like `full_size`, `metadata`,
  # etc.)
  #
  # Implementations should assume that the underlying resource is available,
  # and not try to check for it.
  #
  # @param options [Hash] Empty hash.
  # @return [Boolean,Hash<String,Object>] See the documentation of
  #                                       `pre_authorize()`.
  #
  def authorize(options = {})
    true
  end

  ##
  # Adds additional keys to an Image API 2.x information response. See the
  # [IIIF Image API 2.1](http://iiif.io/api/image/2.1/#image-information)
  # specification and "endpoints" section of the user manual.
  #
  # @param options [Hash] Empty hash.
  # @return [Hash] Hash to merge into an Image API 2.x information response.
  #                Return an empty hash to add nothing.
  #
  def extra_iiif2_information_response_keys(options = {})
    {}
  end

  ##
  # Adds additional keys to an Image API 3.x information response. See the
  # [IIIF Image API 3.0](http://iiif.io/api/image/3.0/#image-information)
  # specification and "endpoints" section of the user manual.
  #
  # @param options [Hash] Empty hash.
  # @return [Hash] Hash to merge into an Image API 3.x information response.
  #                Return an empty hash to add nothing.
  #
  def extra_iiif3_information_response_keys(options = {})
    {}
  end

  ##
  # Tells the server which source to use for the given identifier.
  #
  # @param options [Hash] Empty hash.
  # @return [String] Source name.
  #
  def source(options = {})
  end

  ##
  # N.B.: this method should not try to perform authorization. `authorize()`
  # should be used instead.
  #
  # @param options [Hash] Empty hash.
  # @return [String,nil] Blob key of the image corresponding to the given
  #                      identifier, or nil if not found.
  #
  def azurestoragesource_blob_key(options = {})
  end

  ##
  # N.B.: this method should not try to perform authorization. `authorize()`
  # should be used instead.
  #
  # @param options [Hash] Empty hash.
  # @return [String,nil] Absolute pathname of the image corresponding to the
  #                      given identifier, or nil if not found.
  #
    def filesystemsource_pathname(options = {})
        STDERR.puts "[delegate.filesystemsource_pathname] =========> in filesystemsource_pathname..."

        path = nil

        #
        # test if we have a token that reveals the path
        #
        token = get_token()
        if token
            payload = jwt_payload_from_query_token(token)
            if payload
                path = payload["path"]
            end
        end

        unless path
            #
            # we didn't get the path with the token (missing, expired etc.). Let's try to access the image
            # as user "unknown". Therefore we retrieve the media object as user unknown...
            #
            info = unknown_mediaobject_access(context["identifier"])
            unless info
                STDERR.puts "[delegate.filesystemsource_pathname] No media object for user unknown"
                return nil
            end
            path = info["path"]
        end

        # Prevent traversal via "path"
        STDERR.puts "[delegate.filesystemsource_pathname] path=#{path}"
        subpath = path.to_s.tr("\\", "/")
        clean_subpath = subpath.split("/").reject { |p| p.empty? || p == "." || p == ".." }.join("/")

        full_path = File.join(IMAGE_ROOT, clean_subpath, context["identifier"])
    end

  ##
  # Returns one of the following:
  #
  # 1. String URI
  # 2. Hash with the following keys:
  #     * `uri`               [String] (required)
  #     * `username`          [String] For HTTP Basic authentication
  #                           (optional).
  #     * `secret`            [String] For HTTP Basic authentication
  #                           (optional).
  #     * `headers`           [Hash<String,String>] Hash of request headers
  #                           (optional).
  #     * `send_head_request` [Boolean] Optional; defaults to `true`. See the
  #                           documentation of the
  #                           `HttpSource.BasicLookupStrategy.send_head_requests`
  #                           configuration key.
  # 3. nil if not found.
  #
  # N.B.: this method should not try to perform authorization. `authorize()`
  # should be used instead.
  #
  # @param options [Hash] Empty hash.
  # @return See above.
  #
  def httpsource_resource_info(options = {})
  end

  ##
  # N.B.: this method should not try to perform authorization. `authorize()`
  # should be used instead.
  #
  # @param options [Hash] Empty hash.
  # @return [String, nil] Database identifier of the image corresponding to the
  #                       identifier in the context, or nil if not found.
  #
  def jdbcsource_database_identifier(options = {})
  end

  ##
  # Returns either the last-modified timestamp of an image in ISO 8601 format,
  # or an SQL statement that can be used to retrieve it from a `TIMESTAMP`-type
  # column in the database. In the latter case, the "SELECT" and "FROM" clauses
  # should be in uppercase in order to be autodetected.
  #
  # Implementing this method is optional, but may be necessary for certain
  # features (like `Last-Modified` response headers) to work.
  #
  # @param options [Hash] Empty hash.
  # @return [String, nil]
  #
  def jdbcsource_last_modified(options = {})
  end

  ##
  # Returns either the media (MIME) type of an image, or an SQL statement that
  # can be used to retrieve it from a `CHAR`-type column in the database. In
  # the latter case, the "SELECT" and "FROM" clauses should be in uppercase in
  # order to be autodetected. If nil is returned, the media type will be
  # inferred some other way, such as by identifier extension or magic bytes.
  #
  # @param options [Hash] Empty hash.
  # @return [String, nil]
  #
  def jdbcsource_media_type(options = {})
  end

  ##
  # @param options [Hash] Empty hash.
  # @return [String] SQL statement that selects the BLOB corresponding to the
  #                  value returned by `jdbcsource_database_identifier()`.
  #
  def jdbcsource_lookup_sql(options = {})
  end

  ##
  # N.B.: this method should not try to perform authorization. `authorize()`
  # should be used instead.
  #
  # @param options [Hash] Empty hash.
  # @return [Hash<String,Object>,nil] Hash containing `bucket` and `key` keys.
  #         It may also contain an `endpoint` key, indicating that the endpoint
  #         is different from the one set in the configuration. In that case,
  #         it may also contain `region`, `access_key_id`, and/or
  #         `secret_access_key` keys.
  #
  def s3source_object_info(options = {})
  end

  ##
  # Tells the server what overlay, if any, to apply to an image. Called upon
  # all image requests to any endpoint if overlays are enabled and the overlay
  # strategy is set to `ScriptStrategy` in the application configuration.
  #
  # Return values:
  #
  # 1. For string overlays, a hash with the following keys:
  #     * `background_color` [String] CSS-compliant RGA(A) color.
  #     * `color`            [String] CSS-compliant RGA(A) color.
  #     * `font`             [String] Font name. Launch with the -list-fonts
  #                          argument to see a list of available fonts.
  #     * `font_min_size`    [Integer] Minimum font size in points (ignored
  #                          when `word_wrap` is true).
  #     * `font_size`        [Integer] Font size in points.
  #     * `font_weight`      [Float] Font weight based on 1.
  #     * `glyph_spacing`    [Float] Glyph spacing based on 0.
  #     * `inset`            [Integer] Pixels of inset.
  #     * `position`         [String] Position like `top left`, `center right`,
  #                          etc.
  #     * `string`           [String] String to draw.
  #     * `stroke_color`     [String] CSS-compliant RGB(A) text outline color.
  #     * `stroke_width`     [Float] Text outline width in pixels.
  #     * `word_wrap`        [Boolean] Whether to wrap long lines within
  #                          `string`.
  # 2. For image overlays, a hash with the following keys:
  #     * `image`    [String] Image pathname or URL.
  #     * `position` [String] See above.
  #     * `inset`    [Integer] See above.
  # 3. nil for no overlay.
  #
  # @param options [Hash] Empty hash.
  # @return See above.
  #
  def overlay(options = {})
  end

  ##
  # Tells the server what regions of an image to redact in response to a
  # particular request. Will be called upon all image requests to any endpoint.
  #
  # @param options [Hash] Empty hash.
  # @return [Array<Hash<String,Integer>>] Array of hashes, each with `x`, `y`,
  #         `width`, and `height` keys; or an empty array if no redactions are
  #         to be applied.
  #
  def redactions(options = {})
    []
  end

  ##
  # Returns XMP metadata to embed in the derivative image.
  #
  # Source image metadata is available in the `metadata` context key, and has
  # the following structure:
  #
  # ```
  # {
  #     "exif": {
  #         "tagSet": "Baseline TIFF",
  #         "fields": {
  #             "Field1Name": value,
  #             "Field2Name": value,
  #             "EXIFIFD": {
  #                 "tagSet": "EXIF",
  #                 "fields": {
  #                     "Field1Name": value,
  #                     "Field2Name": value
  #                 }
  #             }
  #         }
  #     },
  #     "iptc": [
  #         "Field1Name": value,
  #         "Field2Name": value
  #     ],
  #     "xmp_string": "<rdf:RDF>...</rdf:RDF>",
  #     "xmp_model": See https://jena.apache.org/documentation/javadoc/jena/org/apache/jena/rdf/model/Model.html,
  #     "xmp_elements": {
  #         "Field1Name": "value",
  #         "Field2Name": [
  #             "value1",
  #             "value2"
  #         ]
  #     },
  #     "native": {
  #         # structure varies
  #     }
  # }
  # ```
  #
  # * The `exif` key refers to embedded EXIF data. This also includes IFD0
  #   metadata from source TIFFs, whether or not an EXIF IFD is present.
  # * The `iptc` key refers to embedded IPTC IIM data.
  # * The `xmp_string` key refers to raw embedded XMP data.
  # * The `xmp_model` key contains a Jena Model object pre-loaded with the
  #   contents of `xmp_string`.
  # * The `xmp_elements` key contains a view of the embedded XMP data as key-
  #   value pairs. This is convenient to use, but may not work correctly with
  #   all XMP fields--in particular, those that cannot be expressed as
  #   key-value pairs.
  # * The `native` key refers to format-specific metadata.
  #
  # Any combination of the above keys may be present or missing depending on
  # what is available in a particular source image.
  #
  # Only XMP can be embedded in derivative images. See the user manual for
  # examples of working with the XMP model programmatically.
  #
  # @return [String,Model,nil] String or Jena model containing XMP data to
  #                            embed in the derivative image, or nil to not
  #                            embed anything.
  #
  def metadata(options = {})
  end

end

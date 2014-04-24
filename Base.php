<?php

namespace RedBrick\Shared\VirusTotal;

/**
 * Class: Base
 *
 * Base functionality for interacting with the VirusTotal API. The Domain, File, Ip, and Url extend this class with
 * resource-specific methods.
 *
 * @author    Brad Melanson <brad.melanson@redbrickmedia.com>
 * @copyright 2014 Red Brick Media
 * @package   RedBrick\Shared\VirusTotal
 * @abstract
 */
abstract class Base
{
    const API_ENDPOINT                   = 'https://www.virustotal.com/vtapi/v2/';
    const MAX_PUBLIC_API_CALL_RESOURCES  = 4;
    const MAX_PRIVATE_API_CALL_RESOURCES = 25;

    protected $_apiKey;
    protected $_client;
    protected $_access;

    /**
     * __construct
     *
     * @param string $api_key                     Your VirusTotal API key.
     * @param string $access                      API access level.
     * @param \GuzzleHttp\ClientInterface $client An instance of a class implementing Guzzle's Client interface. A new 
     *                                            instance of Guzzle's HTTP Client will be generated if left null.
     *
     * @throws \InvalidArgumentException          No API key was provided.
     * @throws \InvalidArgumentException          The API access level was not one of 'public' or 'private'.
     * @return self
     */
    public function __construct( $api_key, $access = 'public', \GuzzleHttp\ClientInterface $client = null )
    {
        if ( empty( $api_key ) )
        {
            throw new \InvalidArgumentException( 'VirusTotal API key must be set.' );
        }

        if ( $access != 'public' && $access != 'private' )
        {
            throw new \InvalidArgumentException( "API access level must be one of 'public' or 'private'" );
        }

        $this->_apiKey  = $api_key;
        $this->_client  = $client ?: new \GuzzleHttp\Client( array( 'base_url' => self::API_ENDPOINT ) );
        $this->_access  = $access;
    }

    /**
     * _sendFile
     *
     * Send a file to VirusTotal.
     *
     * @param string $endpoint    The relative URL to send to. The API_ENDPOINT constant will be prepended if no base URL 
     *                            is set on the Guzzle client.
     * @param resource $file      The file to send.
     *
     * @throws RateLimitException The API rate limit was exceeded.
     * @return string             JSON response from the VirusTotal API.
     */
    protected function _sendFile( $endpoint, $file )
    {
        if ( $this->_client->getConfig( 'base_url' ) === null )
        {
            $endpoint = self::API_ENDPOINT . $endpoint;
        }

        $response = $this->_client->post( $endpoint, array(
            'headers' => array(
                'Content-Type' => 'multipart/form-data'
            ),
            'body' => array(
                'apikey' => $this->_apiKey,
                'file'   => fopen( $file, 'r' )
            )
        ) );

        // VirusTotal's API returns HTTP status code 204 and no response body when the 
        // public API rate limit is exceeded
        if ( $response->getStatusCode() == 204 )
        {
            throw new RateLimitException( 'API Rate limit exceeded.' );
        }

        return $response;
    }

    /**
     * _sendResource
     *
     * Send a resource-identifier hash to VirusTotal.
     *
     * @param string $endpoint    The relative URL to send to. The API_ENDPOINT constant will be prepended if no base URL 
     *                            is set on the Guzzle client.
     * @param string $resource    The resource-identifier hash provided by VirusTotal.
     *
     * @throws RateLimitException The API rate limit was exceeded.
     * @return string             JSON response from the VirusTotal API.
     */
    protected function _sendResource( $endpoint, $resource )
    {
        if ( $this->_client->getConfig( 'base_url' ) === null )
        {
            $endpoint = self::API_ENDPOINT . $endpoint;
        }

        $response = $this->_client->post( $endpoint, array(
            'body' => array(
                'apikey'    => $this->_apiKey,
                'resource'  => $resource
            )
        ) );

        // VirusTotal's API returns HTTP status code 204 and no response body when the 
        // public API rate limit is exceeded
        if ( $response->getStatusCode() == 204 )
        {
            throw new RateLimitException( 'API Rate limit exceeded.' );
        }

        return $response;
    }

    /**
     * _sendUrl
     *
     * Send a URL to VirusTotal.
     *
     * @param string $endpoint    The relative URL to send to. The API_ENDPOINT constant will be prepended if no base URL
     *                            is set on the Guzzle client.
     * @param string $url         The URL to send.
     *
     * @throws RateLimitException The API rate limit was exceeded.
     * @return string             JSON response from the VirusTotal API.
     */
    protected function _sendUrl( $endpoint, $url )
    {
        if ( $this->_client->getConfig( 'base_url' ) === null )
        {
            $endpoint = self::API_ENDPOINT . $endpoint;
        }

        $response = $this->_client->post( $endpoint, array(
            'body' => array(
                'apikey' => $this->_apiKey,
                'url'    => $url
            )
        ) );

        // VirusTotal's API returns HTTP status code 204 and no response body when the 
        // public API rate limit is exceeded
        if ( $response->getStatusCode() == 204 )
        {
            throw new RateLimitException( 'API Rate limit exceeded.' );
        }

        return $response;
    }
}

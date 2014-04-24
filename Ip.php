<?php

namespace RedBrick\Shared\VirusTotal;

/**
 * Class: Ip
 *
 * IP address-specific methods for interacting with the VirusTotal API.
 *
 * @see Base
 *
 * @author    Brad Melanson <brad.melanson@redbrickmedia.com>
 * @copyright 2014 Red Brick Media
 * @package   RedBrick\Shared\VirusTotal
 */
class Ip extends Base
{
    /**
     * getReport
     *
     * Get a report on a given IP address from VirusTotal.
     * NOTE: The VirusTotal API only supports IPV4 addresses.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#getting-ip-reports
     * @link https://www.virustotal.com/en/documentation/private-api/#ip-report
     *
     * @param string $ip_address         The IP address to report on.
     *
     * @throws \InvalidArgumentException An invalid IP address was provided.
     * @throws RateLimitException        The API rate limit was exceeded.
     * @return mixed                     Decoded JSON response from the VirusTotal API.
     */
    public function getReport( $ip_address )
    {
        if ( !filter_var( $ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) )
        {
            throw new \InvalidArgumentException( 'An invalid IP address was submitted.' );
        }

        $endpoint = ( $this->_client->getConfig( 'base_url' ) === null )
            ? parent::API_ENDPOINT . 'ip-address/report' : 'ip-address/report';

        $response = $this->_client->get( $endpoint, array(
            'query' => array(
                'apikey' => $this->_apiKey,
                'ip'     => $ip_address
            )
        ) );

        // VirusTotal's API returns HTTP status code 204 and no response body when the 
        // public API rate limit is exceeded
        if ( $response->getStatusCode() == 204 )
        {
            throw new RateLimitException( 'API Rate limit exceeded.' );
        }

        return $response->json();
    }
}

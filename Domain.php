<?php

namespace RedBrick\Shared\VirusTotal;

/**
 * Class: Domain
 *
 * Domain-specific methods for interacting with the VirusTotal API.
 *
 * @see Base
 *
 * @author    Brad Melanson <brad.melanson@redbrickmedia.com>
 * @copyright 2014 Red Brick Media
 * @package   RedBrick\Shared\VirusTotal
 */
class Domain extends Base
{
    /**
     * getReport
     *
     * Get a report on a given domain from VirusTotal.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#getting-domain-reports
     * @link https://www.virustotal.com/en/documentation/private-api/#domain-report
     *
     * @param string $domain      The domain name to report on.
     *
     * @throws RateLimitException The API rate limit was exceeded.
     * @return mixed              Decoded JSON response from the VirusTotal API.
     */
    public function getReport( $domain )
    {
        $endpoint = ( $this->_client->getConfig( 'base_url' ) === null )
            ? parent::API_ENDPOINT . 'domain/report' : 'domain/report';

        $response = $this->_client->get( $endpoint, array(
            'query' => array(
                'apikey' => $this->_apiKey,
                'domain' => $domain
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

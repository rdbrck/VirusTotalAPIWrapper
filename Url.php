<?php

namespace RedBrick\Shared\VirusTotal;

/**
 * Class: Url
 *
 * URL-specific methods for interacting with the VirusTotal API.
 *
 * @see Base
 *
 * @author    Brad Melanson <brad.melanson@redbrickmedia.com>
 * @copyright 2014 Red Brick Media
 * @package   RedBrick\Shared\VirusTotal
 */
class Url extends Base
{
    /**
     * scan
     *
     * Submit a URL for scanning by VirusTotal.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#scanning-urls
     * @link https://www.virustotal.com/en/documentation/private-api/#url-scan
     *
     * @param string $url                The URL to submit and scan.
     *
     * @throws \InvalidArgumentException An invalid URL was provided.
     * @return mixed                     Decoded JSON response from the VirusTotal API.
     */
    public function scan( $url )
    {
        if ( !filter_var( $url, FILTER_VALIDATE_URL ) )
        {
            throw new \InvalidArgumentException( 'An invalid URL was submitted for scanning.' );
        }

        return $this->_sendUrl( 'url/scan', $url )->json();
    }

    /**
     * scanMultiple
     *
     * Submit multiple URLS for scanning by VirusTotal.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#scanning-urls
     * @link https://www.virustotal.com/en/documentation/private-api/#url-scan
     *
     * @param string[] $urls             An array of URLs to submit and scan.
     *
     * @throws \InvalidArgumentException Too many URLs were provided.
     * @throws \InvalidArgumentException No valid URLs were provided.
     * @return mixed                     Decoded JSON response from the VirusTotal API.
     */
    public function scanMultiple( Array $urls )
    {
        $max = ( $this->_access == 'private' )
            ? parent::MAX_PRIVATE_API_CALL_RESOURCES : parent::MAX_PUBLIC_API_CALL_RESOURCES;

        if ( count( $urls ) > $max )
        {
            throw new \InvalidArgumentException( "Only {$max} URLs can be submitted in a single request." );
        }

        $urls = array_filter( $urls, function( $url ) { return filter_var( $url, FILTER_VALIDATE_URL ); } );

        if ( empty( $urls ) )
        {
            throw new \InvalidArgumentException( 'No valid URLs were submitted for scanning.' );
        }

        $joined_urls = implode( '\n', $urls );

        return $this->_sendUrl( 'url/scan', $joined_urls )->json();
    }

    /**
     * getReport
     *
     * Get a report on a given URL from VirusTotal.
     * NOTE: The allinfo flag is only accepted by the private VirusTotal API.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#getting-url-scans
     * @link https://www.virustotal.com/en/documentation/private-api/#url-report
     *
     * @param string $resource           The submitted URL or the scan ID provided by VirusTotal.
     * @param bool $scan                 Whether to submit the URL for scanning if no report is found.
     * @param bool $allinfo              Whether to include additional data in the response.
     *
     * @throws \InvalidArgumentException The scan flag provided was not a boolean.
     * @throws \InvalidArgumentException The allinfo flag provided was not a boolean.
     * @throws RateLimitException        The API rate limit was exceeded.
     * @return mixed                     Decoded JSON response from the VirusTotal API.
     */
    public function getReport( $resource, $scan = false, $allinfo = false )
    {
        if ( !is_bool( $scan ) )
        {
            throw new \InvalidArgumentException( 'Scan parameter must be true or false.' );
        }

        if ( !is_bool( $allinfo ) )
        {
            throw new \InvalidArgumentException( 'Allinfo parameter must be true or false.' );
        }

        $endpoint = ( $this->_client->getConfig( 'base_url' ) === null )
            ? parent::API_ENDPOINT . 'url/report' : 'url/report';

        $params = array(
            'body' => array(
                'apikey'   => $this->_apiKey,
                'resource' => $resource
            )
        );

        if ( $scan === true )
        {
            $params[ 'body' ][ 'scan' ] = 1;
        }

        if ( $allinfo === true )
        {
            $params[ 'body' ][ 'allinfo' ] = 1;
        }

        $response = $this->_client->post( $endpoint, $params );

        // VirusTotal's API returns HTTP status code 204 and no response body when the 
        // public API rate limit is exceeded
        if ( $response->getStatusCode() == 204 )
        {
            throw new RateLimitException( 'API Rate limit exceeded.' );
        }

        return $response->json();
    }

    /**
     * getReportMultiple
     *
     * Get reports on a group of urls from VirusTotal.
     * NOTE: The allinfo flag is only accepted by the private VirusTotal API.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#getting-url-scans
     * @link https://www.virustotal.com/en/documentation/private-api/#url-report
     *
     * @param string[] $resources        An array of submitted URLs or scan IDs provided by VirusTotal
     * @param bool $scan                 Whether to submit the URLs for scanning if no report is found.
     * @param bool $allinfo              Whether to include additional data in the response.
     *
     * @throws \InvalidArgumentException Too many URLs or resource-identifier hashes were provided.
     * @return mixed                     Decoded JSON response from the VirusTotal API.
     */
    public function getReportMultiple( Array $resources, $scan = false, $allinfo = false )
    {
        $max = ( $this->_access == 'private' )
            ? parent::MAX_PRIVATE_API_CALL_RESOURCES : parent::MAX_PUBLIC_API_CALL_RESOURCES;

        if ( count( $resources ) > $max )
        {
            throw new \InvalidArgumentException( "Only {$max} resources can be submitted in a single request." );
        }

        $joined_resources = implode( ',', $resources );

        return $this->getReport( $joined_resources, $scan, $allinfo );
    }
}

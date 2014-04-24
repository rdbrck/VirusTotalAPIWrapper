<?php

namespace RedBrick\Shared\VirusTotal;

/**
 * Class: File
 *
 * File-specific methods for interacting with the VirusTotal API.
 *
 * @see Base
 *
 * @author    Brad Melanson <brad.melanson@redbrickmedia.com>
 * @copyright 2014 Red Brick Media
 * @package   RedBrick\Shared\VirusTotal
 */
class File extends Base
{
    /**
     * scan
     *
     * Submit a file for scanning by VirusTotal.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#scanning-files
     * @link https://www.virustotal.com/en/documentation/private-api/#scan
     *
     * @param resource $file The file to submit and scan.
     *
     * @return mixed         Decoded JSON response from the VirusTotal API.
     */
    public function scan( $file )
    {
        return $this->_sendFile( 'file/scan', $file )->json();
    }

    /**
     * rescan
     *
     * Rescan an already-submitted file.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#rescanning-files
     * @link https://www.virustotal.com/en/documentation/private-api/#rescan
     *
     * @param string $resource The resource-identifier hash provided by VirusTotal.
     *
     * @return mixed           Decoded JSON response from the VirusTotal API.
     */
    public function rescan( $resource )
    {
        return $this->_sendResource( 'file/rescan', $resource )->json();
    }

    /**
     * getReport
     *
     * Get a report on a given file from VirusTotal.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#getting-file-scans
     * @link https://www.virustotal.com/en/documentation/private-api/#get-report
     *
     * @param string $resource The resource-identifier hash provided by VirusTotal.
     *
     * @return mixed           Decoded JSON response from the VirusTotal API.
     */
    public function getReport( $resource )
    {
        return $this->_sendResource( 'file/report', $resource )->json();
    }

    /**
     * getReportMultiple
     *
     * Get reports on a group of files from VirusTotal.
     *
     * @link https://www.virustotal.com/en/documentation/public-api/#getting-file-scans
     * @link https://www.virustotal.com/en/documentation/private-api/#get-report
     *
     * @param string[] $resources        An array of resource-identifier hashes provided by VirusTotal.
     * 
     * @throws \InvalidArgumentException Too many resource-identifier hashes were provided.
     * @return mixed                     Decoded JSON response from the VirusTotal API.
     */
    public function getReportMultiple( Array $resources )
    {
        $max = ( $this->_access == 'private' )
            ? parent::MAX_PRIVATE_API_CALL_RESOURCES : parent::MAX_PUBLIC_API_CALL_RESOURCES;

        if ( count( $resources ) > $max )
        {
            throw new \InvalidArgumentException( "Only {$max} resources can be submitted in a single request." );
        }

        $joined_resources = implode( ',', $resources );

        return $this->getReport( $joined_resources );
    }
}

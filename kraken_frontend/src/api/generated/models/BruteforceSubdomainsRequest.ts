/* tslint:disable */
/* eslint-disable */
/**
 * kraken
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.5.0
 * Contact: git@omikron.dev
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
/**
 * The settings of a subdomain bruteforce request
 * @export
 * @interface BruteforceSubdomainsRequest
 */
export interface BruteforceSubdomainsRequest {
    /**
     * The leech to use
     * 
     * Leave empty to use a random leech
     * @type {string}
     * @memberof BruteforceSubdomainsRequest
     */
    leechUuid?: string | null;
    /**
     * Domain to construct subdomains for
     * @type {string}
     * @memberof BruteforceSubdomainsRequest
     */
    domain: string;
    /**
     * The wordlist to use
     * @type {string}
     * @memberof BruteforceSubdomainsRequest
     */
    wordlistUuid: string;
    /**
     * The concurrent task limit
     * @type {number}
     * @memberof BruteforceSubdomainsRequest
     */
    concurrentLimit: number;
    /**
     * The workspace to execute the attack in
     * @type {string}
     * @memberof BruteforceSubdomainsRequest
     */
    workspaceUuid: string;
}

/**
 * Check if a given object implements the BruteforceSubdomainsRequest interface.
 */
export function instanceOfBruteforceSubdomainsRequest(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "domain" in value;
    isInstance = isInstance && "wordlistUuid" in value;
    isInstance = isInstance && "concurrentLimit" in value;
    isInstance = isInstance && "workspaceUuid" in value;

    return isInstance;
}

export function BruteforceSubdomainsRequestFromJSON(json: any): BruteforceSubdomainsRequest {
    return BruteforceSubdomainsRequestFromJSONTyped(json, false);
}

export function BruteforceSubdomainsRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): BruteforceSubdomainsRequest {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'leechUuid': !exists(json, 'leech_uuid') ? undefined : json['leech_uuid'],
        'domain': json['domain'],
        'wordlistUuid': json['wordlist_uuid'],
        'concurrentLimit': json['concurrent_limit'],
        'workspaceUuid': json['workspace_uuid'],
    };
}

export function BruteforceSubdomainsRequestToJSON(value?: BruteforceSubdomainsRequest | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'leech_uuid': value.leechUuid,
        'domain': value.domain,
        'wordlist_uuid': value.wordlistUuid,
        'concurrent_limit': value.concurrentLimit,
        'workspace_uuid': value.workspaceUuid,
    };
}


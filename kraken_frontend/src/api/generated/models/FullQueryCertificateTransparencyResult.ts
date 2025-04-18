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
 * A simple representation of a query certificate transparency result
 * @export
 * @interface FullQueryCertificateTransparencyResult
 */
export interface FullQueryCertificateTransparencyResult {
    /**
     * The primary key
     * @type {string}
     * @memberof FullQueryCertificateTransparencyResult
     */
    uuid: string;
    /**
     * The attack which produced this result
     * @type {string}
     * @memberof FullQueryCertificateTransparencyResult
     */
    attack: string;
    /**
     * The point in time, this result was produced
     * @type {Date}
     * @memberof FullQueryCertificateTransparencyResult
     */
    createdAt: Date;
    /**
     * The name of the issuer
     * @type {string}
     * @memberof FullQueryCertificateTransparencyResult
     */
    issuerName: string;
    /**
     * The common name of the certificate
     * @type {string}
     * @memberof FullQueryCertificateTransparencyResult
     */
    commonName: string;
    /**
     * The values of the certificate
     * @type {Array<string>}
     * @memberof FullQueryCertificateTransparencyResult
     */
    valueNames: Array<string>;
    /**
     * The start date of the certificate
     * @type {Date}
     * @memberof FullQueryCertificateTransparencyResult
     */
    notBefore?: Date | null;
    /**
     * The end date of the certificate
     * @type {Date}
     * @memberof FullQueryCertificateTransparencyResult
     */
    notAfter?: Date | null;
    /**
     * The serial number of the certificate
     * @type {string}
     * @memberof FullQueryCertificateTransparencyResult
     */
    serialNumber: string;
}

/**
 * Check if a given object implements the FullQueryCertificateTransparencyResult interface.
 */
export function instanceOfFullQueryCertificateTransparencyResult(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "attack" in value;
    isInstance = isInstance && "createdAt" in value;
    isInstance = isInstance && "issuerName" in value;
    isInstance = isInstance && "commonName" in value;
    isInstance = isInstance && "valueNames" in value;
    isInstance = isInstance && "serialNumber" in value;

    return isInstance;
}

export function FullQueryCertificateTransparencyResultFromJSON(json: any): FullQueryCertificateTransparencyResult {
    return FullQueryCertificateTransparencyResultFromJSONTyped(json, false);
}

export function FullQueryCertificateTransparencyResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): FullQueryCertificateTransparencyResult {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'attack': json['attack'],
        'createdAt': (new Date(json['created_at'])),
        'issuerName': json['issuer_name'],
        'commonName': json['common_name'],
        'valueNames': json['value_names'],
        'notBefore': !exists(json, 'not_before') ? undefined : (json['not_before'] === null ? null : new Date(json['not_before'])),
        'notAfter': !exists(json, 'not_after') ? undefined : (json['not_after'] === null ? null : new Date(json['not_after'])),
        'serialNumber': json['serial_number'],
    };
}

export function FullQueryCertificateTransparencyResultToJSON(value?: FullQueryCertificateTransparencyResult | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'attack': value.attack,
        'created_at': (value.createdAt.toISOString()),
        'issuer_name': value.issuerName,
        'common_name': value.commonName,
        'value_names': value.valueNames,
        'not_before': value.notBefore === undefined ? undefined : (value.notBefore === null ? null : value.notBefore.toISOString()),
        'not_after': value.notAfter === undefined ? undefined : (value.notAfter === null ? null : value.notAfter.toISOString()),
        'serial_number': value.serialNumber,
    };
}


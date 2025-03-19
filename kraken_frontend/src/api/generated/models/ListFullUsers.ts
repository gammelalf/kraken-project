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
import type { FullUser } from './FullUser';
import {
    FullUserFromJSON,
    FullUserFromJSONTyped,
    FullUserToJSON,
} from './FullUser';

/**
 * The response of all users
 * @export
 * @interface ListFullUsers
 */
export interface ListFullUsers {
    /**
     * The list of full users
     * @type {Array<FullUser>}
     * @memberof ListFullUsers
     */
    users: Array<FullUser>;
}

/**
 * Check if a given object implements the ListFullUsers interface.
 */
export function instanceOfListFullUsers(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "users" in value;

    return isInstance;
}

export function ListFullUsersFromJSON(json: any): ListFullUsers {
    return ListFullUsersFromJSONTyped(json, false);
}

export function ListFullUsersFromJSONTyped(json: any, ignoreDiscriminator: boolean): ListFullUsers {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'users': ((json['users'] as Array<any>).map(FullUserFromJSON)),
    };
}

export function ListFullUsersToJSON(value?: ListFullUsers | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'users': ((value.users as Array<any>).map(FullUserToJSON)),
    };
}


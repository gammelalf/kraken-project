/* tslint:disable */
/* eslint-disable */
/**
 * kraken
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.3.5
 * Contact: git@omikron.dev
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import * as runtime from "../runtime";
import type {
    ApiErrorResponse,
    GetFindingFactoryEntriesResponse,
    SetFindingFactoryEntryRequest
} from "../models";
import {
    ApiErrorResponseFromJSON,
    ApiErrorResponseToJSON,
    GetFindingFactoryEntriesResponseFromJSON,
    GetFindingFactoryEntriesResponseToJSON,
    SetFindingFactoryEntryRequestFromJSON,
    SetFindingFactoryEntryRequestToJSON
} from "../models";

export interface SetFindingFactoryEntryOperationRequest {
    setFindingFactoryEntryRequest: SetFindingFactoryEntryRequest;
}

/**
 *
 */
export class FindingFactoryApi extends runtime.BaseAPI {

    /**
     */
    async getFindingFactoryEntriesRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<GetFindingFactoryEntriesResponse>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/v1/admin/finding-factory/entries`,
            method: "GET",
            headers: headerParameters,
            query: queryParameters
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => GetFindingFactoryEntriesResponseFromJSON(jsonValue));
    }

    /**
     */
    async getFindingFactoryEntries(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<GetFindingFactoryEntriesResponse> {
        const response = await this.getFindingFactoryEntriesRaw(initOverrides);
        return await response.value();
    }

    /**
     */
    async setFindingFactoryEntryRaw(requestParameters: SetFindingFactoryEntryOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.setFindingFactoryEntryRequest === null || requestParameters.setFindingFactoryEntryRequest === undefined) {
            throw new runtime.RequiredError("setFindingFactoryEntryRequest", "Required parameter requestParameters.setFindingFactoryEntryRequest was null or undefined when calling setFindingFactoryEntry.");
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters["Content-Type"] = "application/json";

        const response = await this.request({
            path: `/api/v1/admin/finding-factory/entry`,
            method: "PUT",
            headers: headerParameters,
            query: queryParameters,
            body: SetFindingFactoryEntryRequestToJSON(requestParameters.setFindingFactoryEntryRequest)
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     */
    async setFindingFactoryEntry(requestParameters: SetFindingFactoryEntryOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.setFindingFactoryEntryRaw(requestParameters, initOverrides);
    }

}

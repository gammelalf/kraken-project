import React from "react";
import CONSOLE from "./console";

/** Configuration for defining {@link Route routes} */
export interface RouteConfig<UrlParams extends {}, HiddenParams extends {}> {
    /**
     * The route's url as string
     *
     * Use `{<param-name>}` to bind a part of the url to a parameter.
     * For example `user/{username}` binds to the parameter names "username".
     *
     * **Note:**
     * Binding parts of the url is only supported for a whole "directory" in the path.
     * For example `user-{username}` is not supported
     */
    url: string;

    /**
     * Set of functions to parse parameters
     *
     * When a parse function receives invalid input,
     * it should throw an error instead of returning `null` or `undefined`.
     */
    parser: { [Param in keyof UrlParams]: (param: string) => UrlParams[Param] };

    /**
     * Take a set of bound parameters and return the corresponding react element to render
     *
     * @param urlParams parameters parse from an url
     * @param hiddenParams parameters passed through the router
     * @returns react element to show for this route
     */
    render: (urlParams: UrlParams, hiddenParams: HiddenParams | undefined) => React.ReactNode;
}

// @ts-ignore: stupid IDE
/** Regex for a bind parameter in {@link RouteConfig.url `url`} */
const BIND_REGEX = /^\{(.*)}$/;

/** A single route for a [`Router`]{@link Router} */
class Route<UrlParams extends {}, HiddenParams extends {}> {
    /** The route's configuration */
    readonly config: RouteConfig<UrlParams, HiddenParams>;

    /** Pre-split and "parsed" version of {@link RouteConfig.url `config.url`} */
    // eslint-disable-next-line jsdoc/require-jsdoc
    readonly pattern: Array<string | { bind: keyof UrlParams }>;

    /** List of errors the constructor found in the config */
    readonly errors: Array<string>;

    /** Router this route is registered in */
    readonly router: Router;

    /** ID the router identifies this route with */
    readonly id: number;

    /**
     * Constructs a new route for a router
     *
     * Don't call this constructor yourself, use [Router.add]{@link Router#add} instead!
     *
     * @param router the router instance this route will be part of (required for passing hidden params)
     * @param id the id this route will be registered under
     * @param config the route configuration
     */
    constructor(router: Router, id: number, config: RouteConfig<UrlParams, HiddenParams>) {
        this.router = router;
        this.id = id;
        this.config = config;
        if (config.url.length === 0) this.pattern = [];
        else
            this.pattern = config.url.split("/").map((fragment) => {
                const match = fragment.match(BIND_REGEX);
                return match === null ? fragment : { bind: match[1] as keyof UrlParams };
            });
        this.errors = [];

        const occurrence: Set<keyof UrlParams> = new Set();
        for (const pattern of this.pattern) {
            if (typeof pattern === "string") continue;

            if (occurrence.has(pattern.bind)) {
                this.errors.push(`The parameter '${String(pattern.bind)}' appears multiple times in the url pattern`);
            } else {
                occurrence.add(pattern.bind);
            }

            if (this.config.parser[pattern.bind] === undefined) {
                this.errors.push(`The parameter '${String(pattern.bind)}' doesn't have a parser`);
            }
        }

        for (const param of Object.keys(config.parser)) {
            if (!occurrence.has(param as keyof UrlParams)) {
                this.errors.push(`The parameter '${String(param)}' does not appear in the url`);
            }
        }
    }

    /**
     * Try to match an url to this route and parse its parameters
     *
     * @param url an url string which has been split at `/`
     * @returns the parsed url params or `undefined` if the route doesn't match
     */
    match(url: Array<string>): { [Param in keyof UrlParams]: UrlParams[Param] } | undefined {
        if (url.length !== this.pattern.length) return;

        const params: { [Param in keyof UrlParams]?: UrlParams[Param] } = {};
        for (const i in url) {
            const input = url[i];
            const pattern = this.pattern[i];

            if (typeof pattern !== "string") {
                const parser = this.config.parser[pattern.bind];
                try {
                    params[pattern.bind] = parser(input);
                } catch {
                    return;
                }
            } else if (pattern !== input) {
                return;
            }
        }

        return params as { [Param in keyof UrlParams]: UrlParams[Param] };
    }

    /**
     * Build an url to this route using concrete parameters
     *
     * @param urlParams parameters to use
     * @returns the constructed url
     */
    // the signature of `String` takes `any`
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    build(urlParams: { [Param in keyof UrlParams]: any }): string {
        return this.pattern
            .map((pattern) => {
                if (typeof pattern === "string") return pattern;
                else return String(urlParams[pattern.bind]);
            })
            .join("/");
    }

    /**
     * Open this route in the current tab
     *
     * @param urlParams parameters to {@link build `build`} the url with
     * @param hiddenParams parameters to pass to the route's render method through the router instead of the url
     */
    // See `build`
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    visit(urlParams: { [Param in keyof UrlParams]: any }, hiddenParams: HiddenParams | undefined = undefined) {
        const url = this.build(urlParams);
        this.router.setHiddenParams(this, hiddenParams);
        window.location.hash = `/${url}`;
    }

    /**
     * Open this route in a new tab
     *
     * **Beware**
     * Browsers block calls to {@link window.open `window.open`} if they don't occur while handling a user event.
     *
     * @param urlParams parameters to {@link build `build`} the url with
     */
    // See `build`
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    open(urlParams: { [Param in keyof UrlParams]: any }) {
        const url = this.build(urlParams);
        window.open(`${window.location.origin}/#/${url}`);
    }

    /**
     * Return a set of React click handler to make an element behave like a link
     *
     * i.e. left click to open in this tab, middle click to open in new tab
     *
     * @param urlParams parameters to {@link build `build`} the url with
     * @returns object containing React's `onClick` and `onAuxClick` event handler
     */
    // See `build`
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    clickHandler<E>(urlParams: { [Param in keyof UrlParams]: any }): Pick<
        React.HTMLAttributes<E>,
        "onClick" | "onAuxClick"
    > {
        return {
            // eslint-disable-next-line jsdoc/require-jsdoc
            onClick: () => this.visit(urlParams),
            // eslint-disable-next-line jsdoc/require-jsdoc
            onAuxClick: () => this.open(urlParams),
        };
    }
}

/** A router matching a string to routes and parsing their params from it */
export class Router {
    // Changing the array could invalidate the routes' ids
    protected routes: Array<Route<{}, {}>> = [];
    protected hiddenParam:
        | {
              /** The route's id the current hidden params are for*/
              id: number;
              /** The current hidden params (actually of type `HiddenParams` for associated route) */
              params: {};
          }
        | undefined = undefined;

    /**
     * Create a new route and add it to this router
     *
     * @param config the route's config
     * @returns the new route
     */
    add<UrlParams extends {}, HiddenParams extends {}>(
        config: RouteConfig<UrlParams, HiddenParams>,
    ): Route<UrlParams, HiddenParams> {
        const route = new Route(this, this.routes.length, config);
        this.routes.push(route as unknown as Route<{}, {}>);
        return route;
    }

    /**
     * Finalize all routes and log any potential errors
     *
     * TODO this method could post process the list of all route and produce some kind of tree to speed up the url matching process
     */
    finish() {
        for (const route of this.routes) {
            if (route.errors.length > 0) {
                CONSOLE.error(`Errors in route "${route.config.url}":`, ...route.errors);
            }
        }
    }

    /**
     * Set hidden parameters to pass to a route
     *
     * @param route to set parameters for
     * @param hiddenParams parameters to set
     */
    // See `build`
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setHiddenParams<HiddenParams extends {}>(route: Route<any, HiddenParams>, hiddenParams: HiddenParams | undefined) {
        if (this !== route.router) {
            CONSOLE.error("Routes are misconfigured");
            return;
        }
        this.hiddenParam = hiddenParams && { id: route.id, params: hiddenParams };
    }

    /**
     * Match a given pre-split url
     *
     * @param url url already split at "/"
     * @returns the matched route and its parameters, if any
     */
    match(url: Array<string>): [Route<{}, {}>, {}, {} | undefined] | undefined {
        // TODO this naive iter and check step by step could be improved by processing the list in `finish()`
        for (const route of this.routes) {
            const urlParams = route.match(url);
            if (urlParams === undefined) continue;

            let hiddenParams = undefined;
            if (this.hiddenParam) {
                if (this.hiddenParam.id === route.id) hiddenParams = this.hiddenParam.params;
                else this.hiddenParam = undefined;
            }

            return [route, urlParams, hiddenParams];
        }
        return undefined;
    }

    /**
     * Match a given pre-split url and render the routes element
     *
     * @param url url already split at "/"
     * @returns the matched route's [`render`]{@link RouteConfig#render} result, if any
     */
    matchAndRender(url: Array<string>): React.ReactNode | undefined {
        const match = this.match(url);
        if (match === undefined) return undefined;
        const [route, urlParams, hiddenParams] = match;
        return route.config.render(urlParams, hiddenParams);
    }
}

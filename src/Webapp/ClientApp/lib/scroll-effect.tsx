import * as React from "react";
import * as ReactDOM from "react-dom";
import * as classNames from "classnames";

interface Cancelable {
    cancel(): void;
    flush(): void;
}

interface ScrollEffectState {
    animated: boolean;
}

interface ScrollEffectProps {
    animate?: string;
    offset?: number;
    className?: string;
    duration?: number | undefined;
    queueDuration?: number;
    queueClass?: string;
    callback?: () => void;
};

//var canUseDOM = !!(
//    typeof window !== 'undefined' &&
//    window.document &&
//    window.document.createElement
//);

export default class ScrollEffect extends React.Component<ScrollEffectProps, ScrollEffectState> {
    constructor(props: ScrollEffectProps) {
        super(props);
        this.state = {
            animated: false,
        };
    }

    static defaultProps: ScrollEffectProps = {
        animate: "fadeInUp",
        offset: 0,
        className: "",
        duration: 1,
        queueDuration: 1,
        queueClass: "",
        callback: () => {}
    };

    scrollHandler: EventListener & Cancelable;

    componentDidMount() {
        this.handleScroll(undefined);
        this.scrollHandler = debounce(this.handleScroll.bind(this), 200, { trailing: true });
        window.addEventListener("scroll", this.scrollHandler);
    }

    componentWillUnmount() {
        this.scrollHandler.cancel();
        window.removeEventListener("scroll", this.scrollHandler);
    }

    singleAnimate() {
        /* callback */
        setTimeout(() => {
                this.props.callback();
            },
            (this.props.duration | 1) * 1000);
    }

    queueAnimate() {
        const element = ReactDOM.findDOMNode(this);
        const checkClass = (el) => {
            return el.className === this.props.queueClass;
        };
        let number = 0;
        const setClass = (el) => {
            el.style.visibility = "hidden";
            setTimeout(() => {
                    el.style.visibility = "visible";
                    el.className = el.className + " animated " + this.props.animate;
                },
                number * (this.props.queueDuration * 1000));
            number++;
        };
        const findClass = (element) => {
            Array.prototype.forEach.call(element.childNodes,
                function(child) {
                    findClass(child);
                    if (checkClass(child)) {
                        setClass(child);
                    }
                });
        };
        /* find queue classes */
        findClass(element);

        /* callback */
        setTimeout(() => {
                this.props.callback();
            },
            this.props.duration * 1000 * number);
    }

    handleScroll(e) {
        if (!this.state.animated) {
            const element = ReactDOM.findDOMNode(this) as HTMLElement;
            const elementPositionY = element.getBoundingClientRect().top + document.body.scrollTop;
            const scrollPositionY = window.scrollY;
            const windowHeight = window.innerHeight;
            if (scrollPositionY + windowHeight * .95 >= elementPositionY + this.props.offset * 1) {
                this.setState({
                    animated: true
                });
                this.props.queueClass == "" && this.singleAnimate();
                this.props.queueClass !== "" && this.queueAnimate();
            }
        }
    }

    render() {
        const {
            props,
            state
        } = this;

        let classes = classNames({
            'animated': true,
            [props.animate]: state.animated && props.queueClass === ""
        });
        classes += ` ${props.className}`;
        const style: any = state.animated
            ? {}
            : {
                //     visibility: 'hidden'
        
            };
        if (props.duration !== undefined) {
            style.WebkitAnimationDuration = props.duration + "s";
            style.AnimationDuration = props.duration + "s";
        }
        return <div className={classes} style={style}>{props.children}</div>;
    }
}

//let throttle = (delay, callback) => {
//    let previousCall = new Date().getTime();
//    return (...args) => {
//        let time = new Date().getTime();
//        if ((time - previousCall) >= delay) {
//            previousCall = time;
//            callback.apply(null, args);
//        }
//    };
//};
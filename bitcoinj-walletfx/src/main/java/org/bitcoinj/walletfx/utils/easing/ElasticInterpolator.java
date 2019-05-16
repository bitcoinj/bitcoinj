/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2013, Christian Schudt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.bitcoinj.walletfx.utils.easing;

import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;

/**
 * <p>This interpolator simulates an elastic behavior.</p>
 * <p>The following curve illustrates the interpolation.</p>
 * {@code
 * <svg style="width:300px;" xmlns="http://www.w3.org/2000/svg" viewBox="-2 -40 124 140">
 * <line style="stroke: rgb(187, 187, 187); stroke-width: 1px;" y2="60" y1="0" x2="0" x1="0"/>
 * <text style="font-size: 12px; fill: rgb(187, 187, 187);" y="6" x="2">x</text>
 * <line style="stroke: rgb(187, 187, 187); stroke-width: 1px;" y2="60" y1="60" x2="120" x1="0"/>
 * <text style="font-size: 12px; fill: rgb(187, 187, 187);" y="57" x="115">t</text>
 * <path style="fill: rgba(255, 255, 255, 0);stroke: black;stroke-width: 2px;"
 * d="M0,60 L1.2,54.8 2.4,47.7 3.6,39.4 4.8,30.4 6.0,21.2 7.2,12.2 8.4,3.9 9.6,-3.6 10.8,-9.9 12.0,-15.0 13.2,-18.7 14.4,-21.1 15.6,-22.3 16.8,-22.2 18.0,-21.2 19.2,-19.4 20.4,-16.9 21.6,-13.9 22.8,-10.8 24.0,-7.5 25.2,-4.3 26.4,-1.4 27.6,1.3 28.8,3.5 30.0,5.3 31.2,6.6 32.4,7.5 33.6,7.9 34.8,7.9 36.0,7.5 37.2,6.8 38.4,6.0 39.6,4.9 40.8,3.8 42.0,2.7 43.2,1.5 44.4,0.5 45.6,-0.5 46.8,-1.2 48.0,-1.9 49.2,-2.3 50.4,-2.6 51.6,-2.8 52.8,-2.8 54.0,-2.7 55.2,-2.4 56.4,-2.1 57.6,-1.7 58.8,-1.3 60.0,-0.9 61.2,-0.5 62.4,-0.2 63.6,0.2 64.8,0.4 66.0,0.7 67.2,0.8 68.4,0.9 69.6,1.0 70.8,1.0 72.0,0.9 73.2,0.9 74.4,0.7 75.6,0.6 76.8,0.5 78.0,0.3 79.2,0.2 80.4,0.1 81.6,-0.1 82.8,-0.2 84.0,-0.2 85.2,-0.3 86.4,-0.3 87.6,-0.3 88.8,-0.3 90.0,-0.3 91.2,-0.3 92.4,-0.3 93.6,-0.2 94.8,-0.2 96.0,-0.1 97.2,-0.1 98.4,-0.0 99.6,0.0 100.8,0.1 102.0,0.1 103.2,0.1 104.4,0.1 105.6,0.1 106.8,0.1 108.0,0.1 109.2,0.1 110.4,0.1 111.6,0.1 112.8,0.1 114.0,0.0 115.2,0.0 116.4,0.0 117.6,-0.0 118.8,-0.0 120.0,0.0"/>
 * </svg>}
 * <p>The math in this class is taken from
 * <a href="http://www.robertpenner.com/easing/">http://www.robertpenner.com/easing/</a>.</p>
 *
 * @author Christian Schudt
 */
public class ElasticInterpolator extends EasingInterpolator {

    /**
     * The amplitude.
     */
    private DoubleProperty amplitude = new SimpleDoubleProperty(this, "amplitude", 1);

    /**
     * The number of oscillations.
     */
    private DoubleProperty oscillations = new SimpleDoubleProperty(this, "oscillations", 3);

    /**
     * Default constructor. Initializes the interpolator with ease out mode.
     */
    public ElasticInterpolator() {
        this(EasingMode.EASE_OUT);
    }

    /**
     * Constructs the interpolator with a specific easing mode.
     *
     * @param easingMode The easing mode.
     */
    public ElasticInterpolator(EasingMode easingMode) {
        super(easingMode);
    }

    /**
     * Sets the easing mode.
     *
     * @param easingMode The easing mode.
     * @see #easingModeProperty()
     */
    public ElasticInterpolator(EasingMode easingMode, double amplitude, double oscillations) {
        super(easingMode);
        this.amplitude.set(amplitude);
        this.oscillations.set(oscillations);
    }

    /**
     * The oscillations property. Defines number of oscillations.
     *
     * @return The property.
     * @see #getOscillations()
     * @see #setOscillations(double)
     */
    public DoubleProperty oscillationsProperty() {
        return oscillations;
    }

    /**
     * The amplitude. The minimum value is 1. If this value is &lt; 1 it will be set to 1 during animation.
     *
     * @return The property.
     * @see #getAmplitude()
     * @see #setAmplitude(double)
     */
    public DoubleProperty amplitudeProperty() {
        return amplitude;
    }

    /**
     * Gets the amplitude.
     *
     * @return The amplitude.
     * @see #amplitudeProperty()
     */
    public double getAmplitude() {
        return amplitude.get();
    }

    /**
     * Sets the amplitude.
     *
     * @param amplitude The amplitude.
     * @see #amplitudeProperty()
     */
    public void setAmplitude(final double amplitude) {
        this.amplitude.set(amplitude);
    }

    /**
     * Gets the number of oscillations.
     *
     * @return The oscillations.
     * @see #oscillationsProperty()
     */
    public double getOscillations() {
        return oscillations.get();
    }

    /**
     * Sets the number of oscillations.
     *
     * @param oscillations The oscillations.
     * @see #oscillationsProperty()
     */
    public void setOscillations(final double oscillations) {
        this.oscillations.set(oscillations);
    }

    @Override
    protected double baseCurve(double v) {
        if (v == 0) {
            return 0;
        }
        if (v == 1) {
            return 1;
        }
        double p = 1.0 / oscillations.get();
        double a = amplitude.get();
        double s;
        if (a < Math.abs(1)) {
            a = 1;
            s = p / 4;
        } else {
            s = p / (2 * Math.PI) * Math.asin(1 / a);
        }
        return -(a * Math.pow(2, 10 * (v -= 1)) * Math.sin((v - s) * (2 * Math.PI) / p));
    }
}

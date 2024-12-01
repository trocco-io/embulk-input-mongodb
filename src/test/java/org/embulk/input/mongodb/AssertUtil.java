package org.embulk.input.mongodb;

import org.hamcrest.Matcher;

public class AssertUtil
{
    private AssertUtil()
    {
        throw new UnsupportedOperationException();
    }

    @SuppressWarnings("deprecation")
    public static <T> void assertThat(T actual, Matcher<? super T> matcher)
    {
        org.junit.Assert.assertThat(actual, matcher);
    }
}

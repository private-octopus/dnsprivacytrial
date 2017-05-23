#include <stdlib.h>
#include "Cfd.h"



Cfd::Cfd()
    :
    nb_points(0),
    nb_points_alloc(0),
    value(NULL),
    proba(NULL)
{
}


Cfd::~Cfd()
{
    if (value != NULL)
    {
        delete[] value;
    }

    if (proba != NULL)
    {
        delete[] proba;
    }
}

bool Cfd::Load(char * fname)
{
    return false;
}

bool Cfd::AddPoint(double v, double p)
{
    bool ret = true;

    if (nb_points_alloc <= nb_points)
    {
        ret = Resize();
    }

    if (ret && nb_points_alloc > nb_points)
    {
        if (nb_points == 0 || 
            (p > proba[nb_points - 1] ||
                (p == proba[nb_points - 1] && v >= value[nb_points - 1])))
        {
            proba[nb_points] = p;
            value[nb_points] = v;
            nb_points++;
        }
        else
        {
            // Find insertion point
            unsigned int insert_at = 0;

            while (ret && proba[insert_at] < p && insert_at < nb_points)
            {
                ret = v >= value[insert_at];
                insert_at++;
            }

            if (ret)
            {
                if (proba[insert_at] == p && value[insert_at] < v && (insert_at+1) < nb_points)
                {
                    insert_at++;
                }
                else
                {
                    ret = (insert_at < nb_points && v <= value[insert_at]);
                }
            }

            if (ret)
            {
                for (unsigned int i = nb_points; i >= insert_at; i--)
                {
                    proba[i + 1] = proba[i];
                    value[i + 1] = value[i];
                }

                proba[insert_at] = p;
                value[insert_at] = v;
            } 
        }
    }

    return ret;
}

double Cfd::GetProba(double v)
{
    // find the value bounds
    unsigned int compare_at = 0;
    double p = 0;

    while (compare_at < nb_points && value[compare_at] < v)
    {
        compare_at++;
    }

    if (compare_at > 0)
    {
        p = proba[compare_at - 1];

        if (compare_at < nb_points)
        {
            double dp = proba[compare_at] - p;
            double dx = v - value[compare_at - 1];
            if (dp > 0 && dx > 0)
            {
                p += (proba[compare_at] - proba[compare_at - 1])* dx / dp;
            }
        }
    }

    return p;
}

double Cfd::GetValue(double p)
{
    // find the value bounds
    unsigned int compare_at = 0;
    double v = 0;

    while (compare_at < nb_points && proba[compare_at] < p)
    {
        compare_at++;
    }

    if (compare_at > 0)
    {
        v = value[compare_at - 1];

        if (compare_at < nb_points)
        {
            double dv = value[compare_at] - v;
            double dx = v - proba[compare_at - 1];
            if (dv > 0 && dx > 0)
            {
                v += (value[compare_at] - value[compare_at - 1])* dx / dv;
            }
        }
    }

    return v;
}

bool Cfd::Resize()
{
    bool ret = true;
    unsigned int new_size = 128;
    double * np = NULL;
    double * nv = NULL;

    if (nb_points > new_size)
    {
        new_size = 2 * nb_points;
    }

    np = new double[new_size];
    nv = new double[new_size];

    if (np == NULL || nv == NULL)
    {
        ret = false;
        if (np != NULL)
        {
            delete[] np;
        }

        if (nv != NULL)
        {
            delete[] nv;
        }
    }
    else
    {
        if (proba != NULL && value != NULL)
        {
            for (unsigned int i = 0; i < nb_points; i++)
            {
                np[i] = proba[i];
                nv[i] = value[i];
            }
            delete[] proba;
            delete[] value;
        }
        proba = np;
        value = nv;
        nb_points_alloc = new_size;
    }

    return ret;
}
